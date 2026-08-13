"""Web server for watchtower.

A sweep takes 30-60 seconds. Making someone watch a spinner for that long is a
design failure, so results stream: the browser opens an SSE connection and each
source reports in as it lands. The sweep itself runs in a worker thread and
pushes events onto a queue that the response generator drains.

    python run.py serve            # http://127.0.0.1:8000
"""

from __future__ import annotations

import json
import os
import queue
import threading
from dataclasses import asdict
from pathlib import Path

import yaml
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from core import report
from core.enrich import Enricher
from core.fetch import Fetcher
from core.sources import BACKENDS, DEFAULT_BACKENDS
from core.store import Store
from core.sweep import sweep

ROOT = Path(__file__).resolve().parent.parent
STATIC = Path(__file__).resolve().parent / "static"

app = FastAPI(title="watchtower", docs_url="/api/docs")


def config() -> dict:
    return yaml.safe_load((ROOT / "config.yaml").read_text(encoding="utf-8"))


def _sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


# ------------------------------------------------------------------ meta

@app.get("/api/sources")
def list_sources():
    cfg = config()
    enricher = Enricher([], cfg.get("enrichment", {}).get("categories", []))
    # `available` is about credentials actually being present, which is not the
    # same question as `default`. opensanctions is both a default and key-gated,
    # so keying the UI off `default` left it selected and silently returning
    # nothing — the worst possible failure for a sanctions check.
    keyed = {"opensanctions": "OPENSANCTIONS_API_KEY"}
    return {
        "sources": [
            {"name": n, "default": n in DEFAULT_BACKENDS,
             "needs_key": n in keyed,
             "available": n not in keyed or bool(os.environ.get(keyed[n])),
             "key_name": keyed.get(n, "")}
            for n in BACKENDS
        ],
        "ai_available": enricher.enabled,
    }


@app.get("/api/stats")
def stats():
    cfg = config()
    store = Store(ROOT / cfg["storage"]["database"])
    try:
        return store.stats()
    finally:
        store.close()


# ----------------------------------------------------------------- sweep

@app.get("/api/sweep")
def run_sweep(
    q: str = Query(..., min_length=2, max_length=200),
    hours: int = Query(72, ge=1, le=8760),
    sources: str = Query(""),
    use_ai: bool = Query(True),
    fetch_bodies: bool = Query(True),
    save: bool = Query(False),
    limit: int = Query(40, ge=1, le=250),
    max_ai: int = Query(25, ge=0, le=100),
):
    cfg = config()
    backends = [s.strip() for s in sources.split(",") if s.strip()] or DEFAULT_BACKENDS
    unknown = [b for b in backends if b not in BACKENDS]
    if unknown:
        raise HTTPException(400, f"unknown source(s): {', '.join(unknown)}")

    events: queue.Queue = queue.Queue()
    holder: dict = {}

    def work():
        fetcher = None
        try:
            f = cfg["fetch"]
            fetcher = Fetcher(
                user_agent=f["user_agent"],
                delay=f.get("delay_seconds", 2.0),
                timeout=f.get("timeout_seconds", 20),
                obey_robots=f.get("obey_robots", True),
            )
            ec = cfg.get("enrichment", {})
            enricher = None
            if use_ai:
                enricher = Enricher(
                    watchlist=cfg.get("alerts", {}).get("watchlist", []),
                    categories=ec.get("categories", []),
                    escalate_above=ec.get("escalate_above", 60),
                )
            result = sweep(
                q, fetcher, hours=hours, backends=backends, limit=limit,
                fetch_bodies=fetch_bodies, enricher=enricher, max_enrich=max_ai,
                progress=events.put,
            )
            holder["result"] = result
        except Exception as e:
            holder["error"] = f"{type(e).__name__}: {e}"
        finally:
            if fetcher:
                fetcher.close()
            events.put(None)

    threading.Thread(target=work, daemon=True).start()

    def stream():
        yield _sse("start", {"query": q, "sources": backends, "hours": hours})
        while True:
            event = events.get()
            if event is None:
                break
            yield _sse(event.get("type", "progress"), event)

        if "error" in holder:
            yield _sse("failed", {"message": holder["error"]})
            return

        result = holder["result"]
        payload = {
            "query": result.query,
            "enriched": result.enriched,
            "per_source": result.per_source,
            "entities": [{"name": n, "count": c} for n, c in result.entities],
            "errors": result.errors,
            # The frontend needs to tell "searched, found nothing" apart from
            # "could not search" — rendering those the same way is the bug.
            "failed": result.failed,
            "skipped": result.skipped,
            "complete": result.complete,
            "items": [
                {**asdict(i), "band": report.band(i.relevance),
                 "text": i.text[:600]}
                for i in result.items
            ],
        }

        if result.items:
            out_dir = ROOT / cfg["storage"].get("output_dir", "out")
            payload["report"] = report.save(result, out_dir).name
            if save:
                store = Store(ROOT / cfg["storage"]["database"])
                payload["saved"] = store.add(result.items)
                store.close()

        yield _sse("done", payload)

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# --------------------------------------------------------------- archive

@app.get("/api/archive")
def archive(q: str = Query(..., min_length=1), limit: int = Query(30, le=100)):
    cfg = config()
    store = Store(ROOT / cfg["storage"]["database"])
    try:
        rows = store.search(q, limit=limit)
    except Exception as e:
        # FTS5 rejects malformed match syntax; say so rather than 500ing.
        raise HTTPException(400, f"invalid search syntax: {e}")
    finally:
        store.close()
    return {"items": [
        {"title": r["title"], "url": r["url"], "source": r["source"],
         "summary": r["summary"], "relevance": r["relevance"],
         "band": report.band(r["relevance"]),
         "published_at": r["published_at"]}
        for r in rows
    ]}


@app.get("/api/report/{name}")
def get_report(name: str):
    cfg = config()
    out_dir = (ROOT / cfg["storage"].get("output_dir", "out")).resolve()
    path = (out_dir / name).resolve()
    # Contain path traversal: the resolved path must stay inside out_dir.
    if not str(path).startswith(str(out_dir)) or not path.is_file():
        raise HTTPException(404, "report not found")
    return FileResponse(path, media_type="text/markdown", filename=name)


app.mount("/", StaticFiles(directory=STATIC, html=True), name="static")
