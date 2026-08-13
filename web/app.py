"""Web server for watchtower.

A sweep takes 30-60 seconds. Making someone watch a spinner for that long is a
design failure, so results stream: the browser opens an SSE connection and each
source reports in as it lands. The sweep itself runs in a worker thread and
pushes events onto a queue that the response generator drains.

    python run.py serve            # http://127.0.0.1:8000
"""

from __future__ import annotations

import base64
import json
import os
import queue
import secrets
import threading
from dataclasses import asdict
from pathlib import Path

import yaml
from fastapi import Body, FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from core import report
from core.enrich import Enricher
from core.fetch import Fetcher
from core.sources import BACKENDS, DEFAULT_BACKENDS
from core.store import Store
from core.sweep import sweep

# The two tools stay independent of each other; only this layer knows about
# both. scamscan still imports nothing from core/, and core/ imports nothing
# from scamscan — a shared front door is not a shared engine, and the moment
# one starts reaching into the other's store or config that stops being true.
import scamscan

ROOT = Path(__file__).resolve().parent.parent
STATIC = Path(__file__).resolve().parent / "static"

# On a serverless host the deployment bundle is read-only and only /tmp can be
# written. The archive and the generated reports both write, so they have to
# move — but /tmp does not survive between invocations, so anything "saved"
# there is gone by the next request. That is a real limitation, not a detail:
# EPHEMERAL is surfaced through /api/sources so the UI can say so out loud
# rather than letting someone believe they have an archive they don't.
_EXPLICIT_DATA_DIR = os.environ.get("WATCHTOWER_DATA_DIR")
SERVERLESS = bool(os.environ.get("VERCEL") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME"))
DATA_DIR = Path(_EXPLICIT_DATA_DIR) if _EXPLICIT_DATA_DIR else (
    Path("/tmp/watchtower") if SERVERLESS else ROOT)
EPHEMERAL = SERVERLESS and not _EXPLICIT_DATA_DIR

# Wall-clock ceiling for one sweep. A serverless host kills the request at a
# fixed limit with no chance to explain itself, so finish a few seconds early
# and report which sources didn't make it. Unset (no limit) off serverless,
# where a 60s sweep is fine. Keep this below the platform's own timeout —
# vercel.json sets maxDuration to 300, so 270 leaves room to return.
SWEEP_BUDGET = float(os.environ.get("WATCHTOWER_SWEEP_BUDGET",
                                    "270" if SERVERLESS else "0")) or None

app = FastAPI(title="watchtower", docs_url="/api/docs")


def config() -> dict:
    return yaml.safe_load((ROOT / "config.yaml").read_text(encoding="utf-8"))


def data_path(relative) -> Path:
    """Resolve a configured storage path against the writable data directory."""
    p = Path(relative)
    if p.is_absolute():
        return p
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    return DATA_DIR / p


def _sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


# ------------------------------------------------------------------ auth

WT_PASSWORD = os.environ.get("WATCHTOWER_PASSWORD", "")
WT_USER = os.environ.get("WATCHTOWER_USER", "watchtower")


@app.middleware("http")
async def require_password(request, call_next):
    """HTTP Basic, but only once the app is off localhost.

    Locally this is a no-op, because `python run.py serve` binding to 127.0.0.1
    with no password is the documented design and adding a login to it would be
    friction for nothing.

    On a public host it is the opposite: /api/sweep spends real money against
    ANTHROPIC_API_KEY, so an unauthenticated public deployment is someone
    else's budget to burn. With no password set we therefore fail *closed* and
    serve 503 rather than quietly exposing it — a deployment that refuses to
    work is recoverable, one that silently runs up a bill is not.
    """
    if not SERVERLESS:
        return await call_next(request)

    if not WT_PASSWORD:
        return JSONResponse(
            {"detail": "WATCHTOWER_PASSWORD is not set. Refusing to serve a "
                       "public instance without authentication — /api/sweep "
                       "spends real API credits. Set it in the host's "
                       "environment variables and redeploy."},
            status_code=503)

    supplied = request.headers.get("authorization", "")
    expected = "Basic " + base64.b64encode(
        f"{WT_USER}:{WT_PASSWORD}".encode()).decode()
    # Constant-time compare: a plain != leaks the password a byte at a time.
    if not secrets.compare_digest(supplied, expected):
        return JSONResponse(
            {"detail": "authentication required"}, status_code=401,
            headers={"WWW-Authenticate": 'Basic realm="watchtower"'})
    return await call_next(request)


# ------------------------------------------------------------------ meta

@app.get("/api/sources")
def list_sources():
    cfg = config()
    enricher = Enricher([], cfg.get("enrichment", {}).get("categories", []))
    # `available` is about credentials actually being present, which is not the
    # same question as `default`. opensanctions is both a default and key-gated,
    # so keying the UI off `default` left it selected and silently returning
    # nothing — the worst possible failure for a sanctions check.
    keyed = {
        "opensanctions": "OPENSANCTIONS_API_KEY",
        "web_search": "BRAVE_API_KEY",
        "opencorporates": "OPENCORPORATES_API_KEY",
        "x": "X_BEARER_TOKEN",
        "reddit": "REDDIT_CLIENT_ID",
        "bluesky": "BLUESKY_APP_PASSWORD",
    }
    return {
        "sources": [
            {"name": n, "default": n in DEFAULT_BACKENDS,
             "needs_key": n in keyed,
             "available": n not in keyed or bool(os.environ.get(keyed[n])),
             "key_name": keyed.get(n, "")}
            for n in BACKENDS
        ],
        "ai_available": enricher.enabled,
        "ephemeral_storage": EPHEMERAL,
    }


@app.get("/api/stats")
def stats():
    cfg = config()
    store = Store(data_path(cfg["storage"]["database"]))
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
                budget=SWEEP_BUDGET, progress=events.put,
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
            "scoring_error": result.scoring_error,
            "items": [
                {**asdict(i), "band": report.band(i.relevance),
                 "text": i.text[:600]}
                for i in result.items
            ],
        }

        if result.items:
            out_dir = data_path(cfg["storage"].get("output_dir", "out"))
            payload["report"] = report.save(result, out_dir).name
            if save:
                store = Store(data_path(cfg["storage"]["database"]))
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
    store = Store(data_path(cfg["storage"]["database"]))
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


# -------------------------------------------------------------- scamscan

SCAMSCAN_CONFIG = ROOT / "config.json"


def scamscan_config() -> dict:
    try:
        return json.loads(SCAMSCAN_CONFIG.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise HTTPException(503, "config.json is missing — scamscan is not configured")
    except json.JSONDecodeError as e:
        raise HTTPException(503, f"config.json is not valid JSON: {e}")


def scam_band(score, cfg) -> str:
    """Map a score onto the shared relevance ramp.

    The thresholds already mean something — review_threshold is "an analyst
    should look", auto_escalate_threshold is "look now" — so the colour carries
    the same meaning it does on the watchtower side rather than being decoration.
    """
    sc = cfg["scoring"]
    if score >= sc["auto_escalate_threshold"]:
        return "HIGH"
    if score >= sc["review_threshold"]:
        return "MED"
    if score >= sc["review_threshold"] / 2:
        return "LOW"
    return "WEAK"


@app.get("/api/scamscan/status")
def scamscan_status():
    cfg = scamscan_config()
    _, tool_note = scamscan.web_search_tool(cfg)
    lex = cfg["lexicon"]
    unverified = sum(1 for group in lex.values() for entry in group.values()
                     if scamscan.term_weight(entry)[1] in ("", "UNVERIFIED"))
    con = scamscan.db_connect(str(data_path("scamscan.db")))
    try:
        rows = dict(con.execute(
            "SELECT disposition, COUNT(*) FROM findings GROUP BY disposition"
        ).fetchall())
    finally:
        con.close()
    return {
        "brand": cfg["brand"]["name"],
        "topics": len(cfg["seed_topics"]),
        "queries_per_topic": cfg["search"]["queries_per_topic"],
        "max_uses_per_query": cfg["search"]["max_uses_per_query"],
        "model": cfg["search"]["model"],
        "search_tool": tool_note,
        "structured_outputs": bool(cfg["search"].get("structured_outputs", True)),
        "review_threshold": cfg["scoring"]["review_threshold"],
        "escalate_threshold": cfg["scoring"]["auto_escalate_threshold"],
        "lexicon_terms": sum(len(g) for g in lex.values()),
        "counter_terms": len(cfg.get("counter_terms", {})),
        "unverified_terms": unverified,
        # hunt spends money; the UI disables the button rather than letting
        # someone click it and read a 500 as "no scams found".
        "api_available": bool(os.environ.get("ANTHROPIC_API_KEY")),
        "ephemeral_storage": EPHEMERAL,
        "queue": rows,
        "total": sum(rows.values()),
    }


@app.get("/api/scamscan/queue")
def scamscan_queue(
    min_score: float = Query(0, ge=0, le=100),
    disposition: str = Query("new"),
    limit: int = Query(50, ge=1, le=200),
):
    cfg = scamscan_config()
    allowed = {"new", "confirmed", "false_positive", "unclear", "escalated", "all"}
    if disposition not in allowed:
        raise HTTPException(400, f"disposition must be one of {sorted(allowed)}")

    sql = ("SELECT fingerprint, score, scam_type, url, title, summary, evidence, "
           "times_seen, disposition, analyst_note, first_seen, last_seen, breakdown "
           "FROM findings WHERE score >= ?")
    params = [min_score]
    if disposition != "all":
        sql += " AND disposition = ?"
        params.append(disposition)
    sql += " ORDER BY score DESC LIMIT ?"
    params.append(limit)

    con = scamscan.db_connect(str(data_path("scamscan.db")))
    try:
        rows = con.execute(sql, params).fetchall()
    finally:
        con.close()

    items = []
    for (fp, score, stype, url, title, summary, evidence, seen, disp, note,
         first, last, breakdown) in rows:
        try:
            detail = json.loads(breakdown or "{}")
        except json.JSONDecodeError:
            detail = {}
        items.append({
            "fingerprint": fp, "score": score, "band": scam_band(score or 0, cfg),
            "scam_type": stype, "url": url, "title": title, "summary": summary,
            "evidence": evidence, "times_seen": seen, "disposition": disp,
            "analyst_note": note, "first_seen": first, "last_seen": last,
            "breakdown": detail,
        })
    return {"items": items, "ephemeral_storage": EPHEMERAL}


@app.post("/api/scamscan/dispose")
def scamscan_dispose(payload: dict = Body(...)):
    verdicts = {"confirmed", "false_positive", "unclear", "escalated", "new"}
    fingerprint = str(payload.get("fingerprint", "")).strip()
    verdict = str(payload.get("verdict", "")).strip()
    note = str(payload.get("note", ""))[:2000]
    if not fingerprint:
        raise HTTPException(400, "fingerprint is required")
    if verdict not in verdicts:
        raise HTTPException(400, f"verdict must be one of {sorted(verdicts)}")

    con = scamscan.db_connect(str(data_path("scamscan.db")))
    try:
        cur = con.execute(
            "UPDATE findings SET disposition=?, analyst_note=? WHERE fingerprint=?",
            (verdict, note, fingerprint))
        con.commit()
        if not cur.rowcount:
            raise HTTPException(404, "no finding with that fingerprint")
    finally:
        con.close()
    return {"fingerprint": fingerprint, "verdict": verdict, "note": note}


@app.post("/api/scamscan/score")
def scamscan_score(payload: dict = Body(...)):
    """Score pasted text with no API call at all — the `test` command, in a page.

    Free and deterministic, which makes it the right place to tune weights and
    to see why a page scored what it did before spending anything on a hunt.
    """
    cfg = scamscan_config()
    text = str(payload.get("text", ""))[:20000]
    url = str(payload.get("url", ""))[:2000]
    if not text.strip() and not url.strip():
        raise HTTPException(400, "give it some text or a URL to score")

    finding = {"url": url, "title": "", "summary": text, "quoted_evidence": text}
    raw = payload.get("model_confidence")
    if raw not in (None, ""):
        finding["model_confidence"] = raw

    scored = scamscan.score_finding(finding, cfg)
    return {
        **scored,
        "band": scam_band(scored["score"], cfg),
        "review_threshold": cfg["scoring"]["review_threshold"],
        "escalate_threshold": cfg["scoring"]["auto_escalate_threshold"],
    }


@app.get("/api/scamscan/hunt")
def scamscan_hunt(topics: int = Query(1, ge=1, le=20)):
    """Run a discovery pass, streaming the same progress dicts the CLI prints.

    Costs real money per query — web search is billed separately from tokens —
    so `topics` is capped and the UI states the ceiling before you click.
    """
    cfg = scamscan_config()
    if not os.environ.get("ANTHROPIC_API_KEY"):
        raise HTTPException(503, "ANTHROPIC_API_KEY is not set — a hunt needs it")

    events: queue.Queue = queue.Queue()
    holder: dict = {}

    def work():
        con = None
        try:
            con = scamscan.db_connect(str(data_path("scamscan.db")))
            holder["summary"] = scamscan.hunt(
                scamscan.anthropic.Anthropic(), cfg, con, topics, events.put)
        except Exception as e:
            holder["error"] = f"{type(e).__name__}: {e}"
        finally:
            if con:
                con.close()
            events.put(None)

    threading.Thread(target=work, daemon=True).start()

    def stream():
        while True:
            event = events.get()
            if event is None:
                break
            # `done` is emitted by hunt() itself; hold it back so the browser
            # only ever sees one terminal frame, from whichever path ends first.
            if event.get("type") == "done":
                holder.setdefault("summary", event)
                continue
            yield _sse(event.get("type", "progress"), event)

        if "error" in holder:
            yield _sse("failed", {"message": holder["error"]})
            return
        summary = dict(holder.get("summary", {}))
        summary["ephemeral_storage"] = EPHEMERAL
        yield _sse("done", summary)

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/api/report/{name}")
def get_report(name: str):
    cfg = config()
    out_dir = data_path(cfg["storage"].get("output_dir", "out")).resolve()
    path = (out_dir / name).resolve()
    # Contain path traversal: the resolved path must stay inside out_dir.
    if not str(path).startswith(str(out_dir)) or not path.is_file():
        raise HTTPException(404, "report not found")
    return FileResponse(path, media_type="text/markdown", filename=name)


app.mount("/", StaticFiles(directory=STATIC, html=True), name="static")
