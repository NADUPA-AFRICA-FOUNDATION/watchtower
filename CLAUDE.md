# CLAUDE.md

Context for Claude Code sessions in this repo. Read this before changing anything.

## What this is

A monitoring tool for open-source research. Type a keyword, get ranked findings
from news, regulatory sources, social and sanctions lists. Two front doors: a web
UI and a CLI. Same pipeline behind both.

Built for AML/CFT compliance research (adverse media, regulatory change tracking,
entity screening), but nothing in the code is compliance-specific.

## Commands

```bash
pip install -r requirements.txt

python run.py serve                          # web UI, localhost:8000
python run.py sweep "query" --hours 168      # CLI sweep
python run.py run                            # scheduled mode: collect+enrich+alert
python run.py search "kenya AND fraud"       # FTS5 over the archive
python run.py sources                        # list backends
python run.py stats

python smoke_test.py     # store, dedupe, FTS5, alerts
python sweep_test.py     # backends, ranking, renderers, concurrency
python web_test.py       # endpoints, SSE, frontend wiring

python diagnose.py       # hit every real endpoint, report why each one failed
```

Each suite prints its own total; don't hardcode the counts here, they drift.
`diagnose.py` is the first thing to run when a sweep comes back empty — it
reports the actual HTTP status and robots verdict per endpoint.

**Run all three tests after any change.** They use `httpx.MockTransport`, so
they need no network and no API key, and they finish in seconds. If you change
an SSE event name, a CSS class the JS applies, or an element ID, `web_test.py`
catches it — that's what its frontend-wiring section is for.

## Layout

```
core/
  models.py    Item — the one record shape every source produces
  store.py     SQLite + FTS5, dedupe, seen-URL tracking
  fetch.py     HTTP: robots.txt, per-domain rate limit, retries, thread-safe
  clean.py     HTML -> article text (trafilatura, no LLM)
  sources.py   keyword-searchable backends for sweeps
  sweep.py     fan out -> dedupe -> fetch -> rank -> roll up
  enrich.py    Claude scoring and summarisation
  report.py    terminal + markdown renderers, CLI progress formatting
  alerts.py    watchlist matching for scheduled mode
adapters/      rss, gdelt, webpage, social — for scheduled mode
web/
  app.py       FastAPI, SSE streaming
  static/      index.html, style.css, app.js — no build step, no framework
```

## Decisions that should not be reversed without a reason

These were each made deliberately. If you're about to change one, say so
explicitly rather than doing it as a side effect of something else.

**robots.txt is fetched through the shared httpx client, not
`urllib.robotparser.read()`.** urllib opens its own connection, ignores the
configured user agent and timeout, and treats a 403 on `/robots.txt` as
"disallow everything". Behind a corporate proxy that silently kills every fetch
in the app. This was a live bug; the fix is in `fetch.py::allowed`. Status
handling follows RFC 9309: 4xx allow, 5xx back off.

**API calls and crawling are separate activities, and only crawling obeys
robots.txt.** `Fetcher.get(url, api=True)` skips the robots check and is used
by every backend in `core/sources.py`; `api=False` (the default) keeps it and
governs article-body crawling in `sweep.py` and everything in `adapters/`.
robots.txt governs crawlers indexing pages — it is not the access-control
mechanism for a documented public JSON API you are calling as an intended
consumer. `en.wikipedia.org/robots.txt` disallows `/w/`, which is the path of
the API Wikipedia publishes for exactly this purpose and governs with its own
rate-limit and user-agent policy. Applying robots to both silently cost us
every Wikipedia and Google News hit. Do **not** "fix" a blocked source by
setting `obey_robots: false` globally — that removes the protection where it
actually belongs.

**A source that could not be searched never renders as zero.** Backends raise
`SourceError` (blocked, 429, timeout, unparseable body) or `SourceSkipped` (no
credentials) instead of returning `[]`. `sweep.py` sorts these into
`result.failed` and `result.skipped`, kept apart from a genuine zero in
`per_source`, and `SweepResult.complete` is false if either is non-empty. For
screening work this is the whole point: "no adverse media exists" and "we could
not look" must never render the same way, because a clean result that is really
a failed fetch is a false negative someone signs off on. If you add a backend,
raise — do not return `[]` on failure.

**Dedupe is on content hash of title+body, not URL.** One story syndicated to
five outlets under five URLs is one story.

**Claude is only in the scoring layer.** Not fetching, not parsing HTML where a
CSS selector works. Keep it that way — it's slower, costlier and
nondeterministic for those jobs.

**Ranking is two passes.** Free keyword scoring runs over everything; only
plausible candidates reach the model, capped by `--max-ai`. Removing the
prefilter makes every sweep cost real money.

**Cost controls in `enrich.py`:** system block marked for prompt caching (the
`focus` string goes in the user turn so the cached prefix stays identical),
Haiku triages and only items above `escalate_above` get a Sonnet pass, tool use
forces valid JSON. Models: `claude-haiku-4-5-20251001` and `claude-sonnet-5`.

**Instagram, TikTok, LinkedIn and X are deliberately absent.** They prohibit
scraping and fail *silently* — you get empty results and believe you have
coverage. Do not add them, even if asked casually; raise the tradeoff first.
Mastodon is included because it has an open public API.

**Everything degrades without keys — visibly.** No `ANTHROPIC_API_KEY` means
keyword ranking, not a crash. No `OPENSANCTIONS_API_KEY` means that backend
raises `SourceSkipped`, which the sweep records in `result.skipped` and the UI
renders as an "off" lane. It used to return `[]` silently; that was changed
deliberately, because an unsearched sanctions list reported as a clean one is
the most dangerous silent zero in the tool. The sweep still completes and
nothing crashes, so the tool stays testable and demoable without any key.

**Source diversity cap of 3 per domain** in `sweep.py::_diversify`. Without it,
wire copy fills the entire first page.

## Conventions

Adding a sweep source: one function in `core/sources.py` with signature
`(query, fetcher, hours, limit) -> list[Item]`, registered in `BACKENDS`. Nothing
else changes. If a source can't be mapped onto `Item`, that's a signal it needs
its own store rather than a hack to fit.

Progress reporting: `sweep()` calls `progress(dict)`. The CLI renders those via
`report.progress_line`; the web layer forwards them as SSE frames. Neither owns
the format — add a field, don't change existing ones.

Comments explain *why*, not what. Several in this codebase document a trap
(the robots.txt one, the `total_changes` inflation in `store.py::add`, the
relative bar scale in `app.js`). Don't strip them.

Frontend has no build step and no framework. Vanilla JS, `EventSource` for SSE,
CSS custom properties for tokens. Keep it that way — the whole point is that it
runs with `python run.py serve` and nothing else.

## UI design tokens

Defined in `web/static/style.css`. Cool paper ground, quiet everywhere, with
saturated colour reserved for the relevance ramp — if something is coloured, it
means something.

```
--paper #E7ECEF   --surface #FFFFFF  --sunk #DDE4E8
--ink   #0F1A22   --muted   #5C6B76  --faint #8A9AA5  --rule #C6D1D8
ramp: --weak #97A6B0  --low #46748F  --med #B5741A  --high #A82C22
type: IBM Plex Mono (display, labels, all numerics) + IBM Plex Sans (body)
```

Signature element is the sweep trace: source lanes that fill live as each
backend reports in. Don't replace it with a generic spinner — a sweep takes
30-60s and the lanes are what make a silent zero-hit source visible.

## Known gaps

- **The `adapters/` package is missing.** `rss.py`, `gdelt.py`, `webpage.py`
  and `social.py` are not in the tree, so `run.py collect|enrich|alert|run`
  cannot work. `run.py` imports them inside `cmd_collect` rather than at module
  scope so that `serve` and `sweep` — which share none of that code — still
  start. Scheduled mode is dead until those four modules are written.
- **`config.yaml` still ships the placeholder contact `you@example.com`.**
  Wikipedia and SEC EDGAR both want a real contact in the user agent, and a 403
  from EDGAR is usually this. Put a real address in before running anything
  sustained.
- **GDELT rate-limits hard (HTTP 429)** from a single IP, which is what the
  original "58 seconds and nothing" was. It now surfaces as a failed lane
  rather than a zero. Backing off across sweeps, or caching, is unsolved.
- **Mastodon returns a genuine 0** for most queries: unauthenticated status
  search on mastodon.social is heavily restricted. The endpoint is healthy, so
  this reads as a real zero — which may itself be misleading.

Verified in Chrome at 1440 / 820 / 380px on 2026-08-13: layout, the sweep
trace, all four relevance bands, sticky sidebar, keyboard focus rings,
`prefers-reduced-motion`, offline font fallback, empty/error/no-source states,
and that a finished sweep does not silently re-run.
- No authentication on the web server. It binds to localhost. Anything beyond
  that needs a reverse proxy with auth first.
- `adapters/webpage.py` records PDF links but doesn't read them, and regulator
  circulars are usually PDFs. `pypdf` is already listed as an optional dep.
- `config.yaml` ships with a placeholder regulator URL.

## Deployment

Designed to run locally (`python run.py serve`, bound to 127.0.0.1). It is also
deployed to Vercel, which it does not naturally fit — three accommodations make
that work, and all three are visible to the user rather than silent:

- **Storage.** The deployment bundle is read-only, so `DATA_DIR` moves to
  `/tmp/watchtower` when `VERCEL` is set. `/tmp` does not survive between
  invocations, so the archive is ephemeral there. `/api/sources` returns
  `ephemeral_storage: true` and the UI prints a warning, because "Keep results"
  appearing to work and then losing the data is exactly the silent failure this
  codebase exists to avoid. Set `WATCHTOWER_DATA_DIR` to a real mounted volume
  to get persistence back.
- **Auth.** Off localhost the app **fails closed**: with no
  `WATCHTOWER_PASSWORD` set it serves 503 rather than exposing `/api/sweep`,
  which spends real money against `ANTHROPIC_API_KEY`. With one set it requires
  HTTP Basic, compared with `secrets.compare_digest`. Locally it stays
  passwordless, which is the documented design.
- **Time.** `sweep(budget=...)` bounds the wall clock; `SWEEP_BUDGET` defaults
  to 270s under `vercel.json`'s 300s `maxDuration`. Sources that don't finish
  are recorded in `result.skipped` as "exceeded the sweep time budget" — the
  same channel as a missing key, because it is the same fact: not searched.
  The executor is shut down with `wait=False`, otherwise `__exit__` blocks on
  the slowest backend and the budget is cosmetic.

Environment variables: `ANTHROPIC_API_KEY`, `OPENSANCTIONS_API_KEY`,
`WATCHTOWER_PASSWORD`, `WATCHTOWER_USER` (default `watchtower`),
`WATCHTOWER_DATA_DIR`, `WATCHTOWER_SWEEP_BUDGET`. Locally these come from
`.env`, which `run.py` loads and `.gitignore` excludes.

Scheduled mode cannot run on Vercel at all — it needs `adapters/`, which is
missing, and a persistent database.

## Legal and ethical constraints

Not boilerplate — these shape the design.

- `obey_robots: true` stays on by default.
- Rate limiting is per domain, not global.
- `user_agent` in `config.yaml` should carry a real contact address.
- Social posts are personal data. Kenya's Data Protection Act 2019 requires a
  lawful basis, a stated purpose and a retention limit. `RETENTION_DAYS` in
  `adapters/social.py` is enforced on every scheduled run — don't remove the
  purge call.
- Sweeping a named private individual is a different activity from sweeping a
  topic or a company. If a request moves in that direction, flag it rather than
  just building it.

## Good next tasks

Task prompts live in `prompts/`. Start with `prompts/01-verify-ui.md`.

1. **Write the four `adapters/` modules** so scheduled mode runs at all.
   (`prompts/01-verify-ui.md` is done: the UI has been rendered, the overflow
   and `save=true` bugs are fixed, and a "Keep results" toggle now populates
   the archive.)
2. Run a live sweep and tune scoring against real results.
3. PDF extraction pass for `webpage.py`.
4. CSV/JSON export from the web UI.
5. Saved queries that re-run on the GitHub Actions schedule.
