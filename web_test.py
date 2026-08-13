"""Web layer test. Real FastAPI app, real SSE code path, mocked network.

Runs the actual endpoints through Starlette's TestClient with the same canned
responses sweep_test.py uses. Verifies the SSE event contract the frontend
depends on, which is the part most likely to break silently: rename an event
and the browser just sits there showing nothing.

    python web_test.py
"""

import json
import os
import shutil
import sys
import warnings

warnings.filterwarnings("ignore")
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).parent))

from fastapi.testclient import TestClient

import web.app as webapp
from core.fetch import Fetcher
from sweep_test import handler

# Swap the network out from under the app. Everything else is the real thing.
webapp.Fetcher = lambda **kw: Fetcher(
    **{**kw, "delay": 0.0}, transport=httpx.MockTransport(handler))

client = TestClient(webapp.app)


def check(label, cond):
    print(f"  {'PASS' if cond else 'FAIL'}  {label}")
    return bool(cond)


def parse_sse(text):
    """Turn a raw SSE body into [(event, data), ...]."""
    events = []
    name, data = None, None
    for line in text.splitlines():
        if line.startswith("event: "):
            name = line[7:]
        elif line.startswith("data: "):
            data = json.loads(line[6:])
        elif not line.strip() and name:
            events.append((name, data))
            name, data = None, None
    if name:
        events.append((name, data))
    return events


def main():
    ok = True

    print("\nstatic and meta")
    r = client.get("/")
    ok &= check("index serves", r.status_code == 200 and "Watchtower" in r.text)
    ok &= check("stylesheet serves", client.get("/style.css").status_code == 200)
    ok &= check("script serves", client.get("/app.js").status_code == 200)

    r = client.get("/api/sources")
    body = r.json()
    ok &= check("lists every backend", len(body["sources"]) == 7)
    ok &= check("marks defaults", sum(s["default"] for s in body["sources"]) == 6)
    ok &= check("flags the one needing a key",
                any(s["needs_key"] for s in body["sources"]))
    # A key-gated source that is also a default used to ship selected and dead.
    # `available` is what the UI must gate on.
    osrc = next(s for s in body["sources"] if s["name"] == "opensanctions")
    ok &= check("a key-gated source reports whether the key is actually set",
                osrc["available"] == bool(os.environ.get("OPENSANCTIONS_API_KEY")))
    ok &= check("and names the key it wants",
                osrc["key_name"] == "OPENSANCTIONS_API_KEY")
    ok &= check("reports whether scoring is available",
                isinstance(body["ai_available"], bool))
    ok &= check("stats respond", client.get("/api/stats").status_code == 200)

    print("\nvalidation")
    ok &= check("rejects unknown source",
                client.get("/api/sweep?q=test&sources=bogus").status_code == 400)
    ok &= check("rejects a too-short query",
                client.get("/api/sweep?q=a").status_code == 422)
    ok &= check("rejects an absurd window",
                client.get("/api/sweep?q=test&hours=999999").status_code == 422)
    ok &= check("blocks path traversal on reports",
                client.get("/api/report/../config.yaml").status_code == 404)
    r = client.get("/api/archive?q=AND OR")
    ok &= check("bad search syntax returns 400, not 500", r.status_code == 400)
    ok &= check("and explains itself", "syntax" in r.json()["detail"].lower())

    print("\nsweep over SSE")
    r = client.get("/api/sweep?q=beneficial ownership Kenya&hours=72"
                   "&sources=gdelt,google_news,wikipedia&use_ai=false")
    ok &= check("streams as event-stream",
                "text/event-stream" in r.headers["content-type"])
    ok &= check("disables proxy buffering",
                r.headers.get("x-accel-buffering") == "no")

    events = parse_sse(r.text)
    names = [n for n, _ in events]
    ok &= check("opens with start", names[0] == "start")
    ok &= check("closes with done", names[-1] == "done")
    ok &= check("reports each source", names.count("source") == 3)
    ok &= check("reports the dedupe stage", "stage" in names)

    per_source = {d["name"]: d["count"] for n, d in events if n == "source"}
    ok &= check("gdelt lane gets its count", per_source["gdelt"] == 5)
    ok &= check("wikipedia lane gets its count", per_source["wikipedia"] == 1)

    done = events[-1][1]
    ok &= check("payload carries items", len(done["items"]) > 0)
    ok &= check("every item has a band the CSS knows",
                all(i["band"] in ("HIGH", "MED", "LOW", "WEAK")
                    for i in done["items"]))
    ok &= check("items are sorted by score",
                all(done["items"][i]["relevance"] >= done["items"][i + 1]["relevance"]
                    for i in range(len(done["items"]) - 1)))
    ok &= check("body text is capped for transport",
                all(len(i["text"]) <= 600 for i in done["items"]))
    ok &= check("marks keyword-only mode", done["enriched"] is False)
    ok &= check("names the written report", done.get("report", "").endswith(".md"))

    print("\nreport download")
    r2 = client.get(f"/api/report/{done['report']}")
    ok &= check("report downloads", r2.status_code == 200)
    ok &= check("report has content", r2.text.startswith("# Sweep:"))
    (Path(__file__).parent / "out" / done["report"]).unlink(missing_ok=True)

    print("\nno results path")
    r3 = client.get("/api/sweep?q=zzzz nothing&sources=sec_edgar&use_ai=false")
    ev = parse_sse(r3.text)
    ok &= check("still closes with done", ev[-1][0] == "done")
    ok &= check("returns an empty list rather than erroring",
                ev[-1][1]["items"] == [])

    print("\nkeeping results")
    # The Archive tab is dead weight unless the browser can ask for save=true,
    # so assert the round trip rather than just the checkbox existing. Point
    # the store at a scratch DB first — a test must never write fixture rows
    # into the archive the user actually reads.
    import tempfile
    real_config = webapp.config
    tmpdir = tempfile.mkdtemp()
    webapp.config = lambda: {**real_config(),
                             "storage": {"database": f"{tmpdir}/test.db",
                                         "output_dir": tmpdir}}
    try:
        r4 = client.get("/api/sweep?q=beneficial ownership Kenya&sources=gdelt"
                        "&use_ai=false&fetch_bodies=false&save=true")
        kept = parse_sse(r4.text)[-1][1]
        ok &= check("save=true reports how many rows it stored",
                    isinstance(kept.get("saved"), int))
        r5 = client.get("/api/sweep?q=beneficial ownership Kenya&sources=gdelt"
                        "&use_ai=false&fetch_bodies=false")
        ok &= check("and stores nothing without it",
                    "saved" not in parse_sse(r5.text)[-1][1])
    finally:
        webapp.config = real_config
        shutil.rmtree(tmpdir, ignore_errors=True)

    print("\nfrontend wiring")
    import re
    static = Path(__file__).parent / "web" / "static"
    html = (static / "index.html").read_text()
    js = (static / "app.js").read_text()
    css = (static / "style.css").read_text()

    html_ids = set(re.findall(r'id="([^"]+)"', html))
    js_ids = set(re.findall(r'\$\("#([a-zA-Z0-9_-]+)"\)', js))
    ok &= check("every element the script reaches for exists",
                not (js_ids - html_ids))

    js_classes = set(re.findall(r'el\("[a-z0-9]+", "([a-z-]+)"', js))
    js_classes |= set(re.findall(r'classList\.(?:add|toggle)\("([a-z-]+)"\)', js))
    css_classes = set(re.findall(r'\.([a-zA-Z][\w-]*)', css))
    ok &= check("every class the script applies is styled",
                not (js_classes - css_classes))

    js_events = set(re.findall(r'addEventListener\("(\w+)"', js))
    ok &= check("the script handles every event the server sends",
                {"source", "stage", "scored", "done", "failed"} <= js_events)

    ok &= check("the sweep request carries the save flag", "save:" in js)
    # Source-controlled text (titles, URL slugs, entity names) has no spaces to
    # wrap at. Without these the longest token sets the column width and the
    # whole page scrolls sideways — worst at 380px. See the note in style.css.
    for sel in (".card h3", ".card p.body", ".tag", ".panel li span"):
        ok &= check(f"{sel} can break an unbreakable string",
                    re.search(re.escape(sel) + r"[^{]*\{[^}]*overflow-wrap:\s*anywhere",
                              css) is not None)
    ok &= check("the favicon is inline, so a clean load logs no 404",
                'rel="icon"' in html)
    # showEmpty() hides #results, which is where the Problems panel lives, so a
    # zero-hit sweep caused by six broken sources would otherwise explain
    # nothing. The rendering itself needs a browser; this checks the wiring.
    ok &= check("a zero-result sweep passes the coverage reasons through",
                re.search(r"showEmpty\([^;]*notes\)", js) is not None)
    ok &= check("and the empty-state error block is styled",
                ".empty-errs" in css)
    # The whole point of task 02: an empty sweep with a broken source must not
    # render the same as an empty sweep where everything answered.
    ok &= check("the empty state branches on whether coverage was complete",
                "d.complete === false" in js)
    ok &= check("a failed lane is labelled, not shown as 0",
                'd.error ? "failed"' in js)
    ok &= check("an unsearched lane is labelled too", 'd.skipped ? "off"' in js)
    ok &= check("chips gate on the key being present, not on being a default",
                "s.available !== false" in js)
    for cls in (".lane.skipped", ".summary .warn"):
        ok &= check(f"{cls} is styled", cls in css)

    print("\n" + ("ALL CHECKS PASSED" if ok else "SOME CHECKS FAILED") + "\n")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
