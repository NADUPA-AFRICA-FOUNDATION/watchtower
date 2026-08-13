# scamscan

> One of two tools in this repo. See [README.md](README.md) for **watchtower**,
> the multi-source keyword sweep. They share nothing but the repo.

Keyword-driven scam discovery using Claude's server-side web search.

Claude proposes candidates; local Python code scores them. Anything that drives
analyst workload is computed in auditable code, not inside a prompt.

## Setup

```bash
pip install anthropic
export ANTHROPIC_API_KEY=sk-ant-...      # from platform.claude.com -> Settings -> API keys
python scamscan.py hunt --config config.json --topics 1   # start with one topic
```

## Commands

| Command | What it does |
|---|---|
| `hunt` | Expand seed topics into queries, search, extract, score, store |
| `queue` | Print the review queue, highest score first |
| `export --out queue.csv` | Dump everything to CSV |
| `dispose <fingerprint> confirmed\|false_positive\|unclear\|escalated` | Record an analyst verdict |
| `test "<text>" --url <url>` | Score sample text offline, no API calls |

Use `test` heavily before your first real run. It costs nothing and it is how you
tune weights against examples you already know the answer to.

## How scoring works

Four independent families, each 0-100, averaged with configurable weights:

- **lexicon** — weighted term hits across English, Kiswahili and Sheng
- **artifact** — extracted phone numbers, paybills, tills, WhatsApp/Telegram
  links, crypto addresses, shortlinks, and explicit PIN/OTP requests
- **impersonation** — host similarity to official domains after NFKD
  normalisation and homoglyph folding, plus brand tokens and credential-themed
  hostnames. Official domains are hard-zeroed
- **model** — Claude's own confidence, as one vote among four rather than the
  verdict

Change `scoring.weights` in `config.json` to shift the balance. Drop `model` to
0 if you want a fully deterministic pass.

## Cost

Web search is billed separately from tokens, at roughly $10 per 1,000 searches.
With `queries_per_topic: 3` and `max_uses_per_query: 4`, one topic costs up to 12
searches. Six topics is up to 72 searches per run, so roughly $0.72 plus tokens.
A daily run across six topics lands near $25/month. Start with `--topics 1`.

## Dedupe

Fingerprint is the registrable domain plus a hash of the first 25 words of the
summary. Same site with the same copy collapses and increments `times_seen`.
Different site with the same copy stays separate on purpose — cross-site
duplication is the coordination signal you want to see, not noise to suppress.

## Prompt injection

Pages returned by search are untrusted data. The hunt prompt says so explicitly,
and scoring never executes anything from page content. If a page contains text
addressed to the model, that gets reported as evidence rather than followed.
Keep this property if you extend the tool: never let extracted content reach a
shell, a SQL string, or a follow-up prompt as an instruction.

## Known limits

- Only reaches the indexed web. Closed Facebook groups, Telegram channels,
  WhatsApp and most video content are invisible here. Those need separate pipes.
- Search index freshness lags. Certificate Transparency monitoring catches
  lookalike domains days earlier and costs nothing.
- Kenyan phone patterns are hardcoded in `ARTIFACT_PATTERNS`. Add Tanzania
  (+255) and Lesotho (+266) before running those markets.
- The lexicon shipped here is a placeholder. Rebuild it from real reported cases;
  invented terms will underperform badly.

## Compliance

This collects and stores data about identifiable people. Before running it
against live traffic in an employer context, confirm the lawful basis, whether a
DPIA is required, retention limits, and who may access the queue. Do not join
findings to internal customer records without that sign-off.
