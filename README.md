# watchtower

> This repo holds two tools. **watchtower** (this file) sweeps many sources
> for a keyword. **scamscan** ([SCAMSCAN.md](SCAMSCAN.md)) hunts live scam
> pages with Claude's server-side web search. They share nothing but the repo.

Type a keyword, get ranked findings across news, regulatory sources, social and
sanctions lists. Also runs as a scheduled monitor once you know what to watch.

```bash
python run.py serve      # web UI at http://127.0.0.1:8000
python run.py sweep "beneficial ownership Kenya" --hours 168    # or CLI
```

## Setup

```bash
bash setup.sh              # creates .venv, installs deps, runs all tests
source .venv/bin/activate
export ANTHROPIC_API_KEY=sk-...    # optional
python run.py serve
```

Open <http://127.0.0.1:8000>, type a query, hit Sweep. No config file needed,
no API key required to get results.

## The web UI

A sweep takes 30-60 seconds, so nothing blocks: results stream over SSE and each
source fills its lane as it reports in. Two views — **Sweep** for live queries,
**Archive** for full-text search over anything you've saved.

Controls map to the CLI flags: lookback window, which sources to hit, whether to
read full article bodies, whether to score with Claude. Options that need a key
you haven't set are disabled with a tooltip saying which one.

```bash
python run.py serve --host 0.0.0.0 --port 9000
```

It binds to localhost by default. There is no authentication — put it behind a
reverse proxy with auth before exposing it to anything.

That's it. No config needed for sweeps, no API key required to get results.
Without a key you lose relevance scoring, summaries and entity extraction, and
fall back to keyword-overlap ranking.

## What a sweep does

```
fan out across sources -> dedupe -> fetch bodies -> clean
    -> keyword prefilter -> Claude scores the survivors -> rank -> report
```

Results print to the terminal; a full markdown report lands in `out/`.

| Source | What it gives you | Key needed |
|---|---|---|
| `gdelt` | global news, all languages, 15-min lag | no |
| `google_news` | broad news, good local outlet recall | no |
| `wikipedia` | entity background, disambiguation | no |
| `hackernews` | tech and fintech chatter | no |
| `mastodon` | public social posts | no |
| `opensanctions` | sanctions, PEP and watchlist matches | free key |
| `sec_edgar` | US filings full-text | no |

```bash
python run.py sources                                     # list them
python run.py sweep "acme ltd" --sources gdelt,opensanctions
python run.py sweep "crypto licensing" --hours 720 --top 40
python run.py sweep "quick look" --no-fetch --no-ai       # seconds, headlines only
python run.py sweep "acme ltd" --save                     # keep it in the archive
```

Flags: `--hours` lookback, `--limit` per-source cap, `--max-ai` cap on items
sent to the model, `--top` how many print, `--sources` which backends.

GDELT accepts operators inside the query string: `sourcecountry:KE`,
`sourcelang:english`, `domain:example.co.ke`, `"exact phrase"`, `(a OR b)`.

## Scheduled monitoring

Once a sweep shows a topic is worth watching, move it into `config.yaml` and let
it run on a schedule.

```bash
python run.py run                # collect + enrich + alert
python run.py search "kenya AND (fraud OR laundering)"
python run.py stats
```

`.github/workflows/monitor.yml` runs this twice daily on a free GitHub runner
and commits results back to the repo. That's the whole deployment — no server.

Adapters for scheduled mode: `rss` (start here), `gdelt`, `webpage` (link-diff
on regulator listing pages, survives redesigns), `social` (Reddit via PRAW).
Point `rss` at a self-hosted [RSSHub](https://github.com/DIYgod/RSSHub) and a
lot of feed-less sites become feeds.

## Design notes

**Dedupe is on content hash, not URL.** One story syndicated to five outlets
under five URLs is one story.

**Two ranking passes.** A free keyword pass runs over everything; only plausible
candidates reach the model. That's what keeps a sweep cheap.

**Source diversity cap.** Three results per domain up top, so wire copy can't
occupy your entire first page.

**Claude sits in scoring only** — not in fetching, and not in parsing HTML where
a CSS selector works. Cost controls already in the code: text is cleaned and
truncated first, the instruction block is marked for prompt caching, Haiku
triages and only items above `escalate_above` get a Sonnet pass, and tool use
forces valid JSON so nothing regex-parses model prose.

**robots.txt goes through the same client as everything else.** urllib's
`RobotFileParser.read()` opens its own connection, ignores your user agent and
timeout, and treats a 403 as "disallow everything" — which silently kills every
fetch behind a proxy. This bug was live in the first version and the test caught
it.

## Tests

```bash
python smoke_test.py        # store, dedupe, FTS5, alert triggers      (21)
python sweep_test.py        # backend parsers, dedupe, concurrent      (31)
                            # fetch, ranking, both renderers
python web_test.py          # endpoints, SSE contract, validation,     (33)
                            # path traversal, frontend wiring
```

Both `sweep_test.py` and `web_test.py` inject an `httpx.MockTransport`, so only
the network is replaced — the code under test is the real thing, including the
FastAPI app and the SSE stream. If they pass but a live sweep returns nothing,
the problem is the remote API or your connection, not the install.

The web UI has now been rendered and checked in Chrome at 1440, 820 and 380px,
including the empty, connection-lost and no-source-selected states. Not covered:
scheduled mode, which cannot run until the missing `adapters/` modules exist.

## Before you point it at anything

- `obey_robots: true` stays on. It's the line between automated collection and
  unauthorised access if anyone ever asks.
- Rate limiting is per domain, not global, and thread-safe.
- Put a real contact address in `user_agent`. Site owners who can reach you will
  email before they block you.
- Social posts are personal data. Under Kenya's Data Protection Act 2019 you
  need a lawful basis, a stated purpose and a retention limit. `RETENTION_DAYS`
  in `adapters/social.py` is enforced on every scheduled run.
- Instagram, TikTok, LinkedIn and X are absent on purpose. They prohibit
  scraping and fail *silently*, which is the worst failure mode for monitoring:
  you believe you have coverage and you don't. Mastodon is here because it has
  an open public API.
- Sweeping a named private individual is a different activity from sweeping a
  topic or a company, legally and ethically. Know which one you're doing.

## Working on this with Claude Code

`CLAUDE.md` in the repo root is loaded automatically each session. It carries the
architecture, the decisions that shouldn't be silently reversed, the UI design
tokens, and the known gaps. Keep it current — when you change something
structural, update it in the same commit.

```bash
cd watchtower
git init && git add -A && git commit -m "initial"
claude
```

Run the three test suites after every change. They need no network and no API
key, so there's no excuse to skip them.

## Extending

Add a source by writing one function in `core/sources.py` with the signature
`(query, fetcher, hours, limit) -> list[Item]` and registering it in `BACKENDS`.
Nothing else changes.
