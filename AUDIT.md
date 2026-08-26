# Watchtower / ScamScan functional and UI/UX audit

Audit date: 2026-08-26

## Executive summary

The repository contains **280 Python function or method definitions**. It is not
possible to honestly claim that every definition works merely because the four
scripted suites pass: the suites are behavioural checks, not line/branch
coverage, and live providers cannot be verified without credentials and paid
requests. Within that boundary, the offline test baseline is healthy:

| Suite | Result | What it establishes |
|---|---|---|
| `python smoke_test.py` | pass | cleaning, models, storage, FTS, alerts, adapters and retention |
| `python sweep_test.py` | pass | sources, ranking, retries, concurrency, deadlines and reporting |
| `python web_test.py` | pass | endpoints, validation, SSE contracts and frontend wiring |
| `python scamscan_test.py` | pass | offline scoring, schemas, provider failure shapes and silent-zero protection |
| `python -m compileall -q .` | pass | every Python file parses and compiles |

**Confirmed non-working functions in the exercised offline surface: none.**
That is a narrower and more defensible statement than “every function works.”
The unverified areas below must not be represented to an analyst as working
coverage until their live contract checks have run.

## Function audit and verification gaps

### P0 — must be explicit before operational use

1. **Live third-party source functions are not verified by offline mocks.**
   `core.sources` includes GDELT, Google News, Wikipedia, Hacker News,
   Mastodon, SEC EDGAR, OpenSanctions, Brave, GLEIF, OpenCorporates, Bluesky,
   Reddit and X. Mock fixtures prove our parsers against known response shapes;
   they do not prove that credentials, quotas, endpoint versions or current
   upstream payloads work. Run `python diagnose.py` and a one-source canary for
   each enabled provider. Record the check time and response class in the UI.

2. **Paid model/search paths remain environment-dependent.** Anthropic and
   Gemini calls, including ScamScan grounding, require live credentials and can
   spend money. The offline suites correctly test error shapes, but cannot prove
   account balance, model access or current tool compatibility. Keep hunting
   disabled until `/api/scamscan/status` reports a usable provider; add an
   administrator-only canary and display its last success.

3. **Persistence is intentionally non-persistent on Vercel.** Archive writes
   and analyst dispositions can disappear from `/tmp`. Disable **Keep results**
   and verdict-changing controls when durable storage is unavailable, rather
   than allowing an action whose result will be lost. A visible warning is
   useful but is weaker than preventing a misleading action.

4. **Completeness is not coverage.** A technically successful Mastodon search
   may return zero because anonymous search is restricted. Label results as
   “limited coverage,” not simply “0,” and keep them out of any “all sources
   searched” assurance until an authenticated, documented coverage contract is
   available.

### P1 — targeted tests needed

5. Add branch coverage reporting (`pytest`/`coverage.py` or the existing script
   harness under coverage) and set an initial ratchet, not an arbitrary 100%
   gate. Prioritise `core/fetch.py`, `core/sweep.py`, `web/app.py`, database
   migrations and provider dispatch in `scamscan.py`.
6. Add database corruption, concurrent writer, disk-full and read-only-volume
   tests. Current happy-path persistence tests do not establish recovery.
7. Add contract fixtures captured from every live API, scrubbed of credentials
   and personal data, plus scheduled canaries that fail loudly when shapes
   drift.
8. Add browser automation for keyboard-only use, focus order, back/forward
   navigation, screen-reader names, zoom at 200%, high-contrast mode and
   JavaScript/network failures. Static wiring checks cannot establish these.
9. Add load and cancellation tests for multiple simultaneous SSE clients. Test
   disconnect cleanup and confirm abandoned sweeps do not continue spending API
   credits.

## UI/UX audit

The interface is better described as an **analyst investigation console** than
a generic dashboard. The two products should be named consistently by their
jobs:

- **Monitor** (currently “Sweep”): search current sources for a topic.
- **Saved results** (currently “Archive”): find deliberately retained results.
- **Find scam sites** (currently “Discover”): create OSINT leads from public
  search evidence.
- **Review queue** (currently “Queue”): triage and disposition saved leads.
- **Quick score** (currently “Score”): score pasted evidence locally.

This uses action + object labels, reduces internal jargon, and separates the
Watchtower and ScamScan mental models. Keep “Sweep” as optional domain language
in help text, not as the only navigation cue.

### What already follows sound UI/UX principles

- The page uses a small, consistent token system and reserves saturated colour
  for meaningful relevance levels.
- Labels are attached to primary fields; hints explain syntax and cost.
- Long-running tasks expose progressive source lanes instead of a spinner.
- Empty, failed and unsearched states are distinct—critical feedback and error
  prevention for compliance work.
- Key-dependent sources and model scoring are disabled when unavailable.
- Native controls, focus styles, responsive layouts and reduced-motion support
  provide a sound accessibility base.
- Scam candidates are described as leads rather than confirmed facts, matching
  the language to the user's real decision.

### Usability and accessibility improvements

| Priority | Principle | Finding | Recommendation / acceptance check |
|---|---|---|---|
| P0 | Error prevention | Durable and ephemeral actions look alike. | Disable save/disposition actions without durable storage; explain inline how to enable them. |
| P0 | User control | Long sweeps and billed hunts have no explicit cancel control. | Add **Cancel** beside the running action, close SSE, cancel queued work and show whether already-issued calls may still bill. |
| P0 | Visibility | Provider health is compressed into a small status indicator and tooltips. | Add a labelled **Coverage & system status** panel with enabled, limited, failed, last checked and credential owner states. Never rely on colour or hover alone. |
| P0 | Error recovery | Fetch/stream failures mainly end in prose. | Give errors a short cause, retained inputs, **Retry failed sources**, and a copyable diagnostic ID. Move focus to an error summary. |
| P1 | Match to users | “Sweep,” “Discover,” “Queue,” and “Score” require product knowledge. | Adopt the action labels above; validate with five representative analysts using first-click tasks. |
| P1 | Progressive disclosure | Source selection, sanctions, depth and retention choices appear before a novice can form a basic query. | Default to a safe “Standard search”; place sources and model/cost options in **Advanced options**, while keeping sanctions visibly separate. |
| P1 | Consistency | Watchtower and ScamScan share a rail but have different workflows and event terms. | Add a persistent product heading and one-sentence purpose; preserve explicit `unsearched` versus `failed` wording. |
| P1 | Recognition | Score bands such as review/escalate are unexplained at the decision point. | Add a compact legend describing thresholds, evidence families and “unknown is not safe.” |
| P1 | Accessibility | Custom button radiogroups initialise `aria-checked` only on selected choices. | Give every radio an explicit state, implement arrow-key movement/roving tabindex, and verify with axe plus keyboard tests. |
| P1 | Navigation | Tabs are buttons and view state is not linkable. | Use links/routes or update history and focus on view change; support refresh, deep links and browser Back. |
| P2 | Minimalism | Large configuration blocks compete with results. | Collapse completed forms into a run summary while results are visible; provide **Edit search**. |
| P2 | Help | Operator syntax and compliance warnings are present but scattered. | Add task-based examples, a glossary, and contextual “Why?” disclosures for cost, retention, scores and incomplete coverage. |
| P2 | Responsive use | Dense cards can become lengthy on mobile. | Prioritise score, source, title and primary action; collapse evidence details with accessible disclosure controls. |

These recommendations apply the referenced cheat sheet's core themes—clarity,
consistency, hierarchy, feedback, accessibility, simplicity and user-centred
validation—without treating a generic checklist as proof of usability.

## Features and integrations to disable or gate

1. **Disable billed hunts by default** until a provider canary succeeds; require
   explicit cost acknowledgement and enforce per-run and daily budgets server
   side, not only a `topics` input cap.
2. **Disable model scoring when all providers are unhealthy**, not merely when
   keys are absent. Fall back visibly to keyword ranking.
3. **Disable retention-dependent actions on ephemeral storage**, including Keep
   results and analyst dispositions.
4. **Disable sources after repeated authentication/schema failures** with a
   circuit breaker and visible reason; allow administrators to retry.
5. **Disable scraped social platforms** unless a documented official/research
   API and lawful basis are available. Do not turn silent scraping into apparent
   coverage.
6. **Gate exports containing personal data** behind role-based access, audit
   logging, retention policy and explicit redaction options.
7. **Gate destructive queue actions and bulk disposition** behind confirmation,
   undo and an immutable audit trail.

## APIs and system capabilities to add

### P0 foundation

- **Authentication and authorisation:** an identity provider using OIDC, roles
  for viewer/analyst/admin, session expiry and CSRF protection for mutations.
- **Durable managed storage:** PostgreSQL (or another supported persistent
  store), migrations, encrypted backups, restore drills and record retention.
- **Audit API:** append-only actor/action/time/reason records for searches,
  exports, verdicts and configuration changes.
- **Health/coverage API:** per dependency status, last successful contract
  check, latency, quota state and degraded-mode reason. Never expose secrets.
- **Job API:** durable jobs with idempotency keys, cancellation, status polling
  and resumable event streams instead of tying expensive work to one browser
  connection.

### P1 analyst workflow

- Saved searches/watchlists with schedule, owner, purpose, retention and alert
  destination.
- JSON/CSV export for Watchtower with provenance, run completeness, timestamps
  and redaction; do not export a score without its evidence breakdown.
- Case-management integration via webhooks and a documented API (for example,
  create/update a case after an analyst confirms a lead).
- Notification adapters for email/Slack/Teams with deduplication, severity
  thresholds and links back to the exact retained evidence.
- Threat-intelligence interchange such as STIX/TAXII where the receiving
  organisation already supports it; map confidence and provenance explicitly.
- URL/domain reputation providers (for example URLhaus, PhishTank or
  OpenPhish) only through their documented terms, with cache age displayed.
- RDAP/DNS/TLS enrichment with timeouts and timestamps. Treat absence as
  unknown rather than benign.

### P2 quality and operations

- OpenTelemetry traces/metrics, privacy-safe structured logs and cost metrics
  per provider/run.
- Feature flags and configuration validation so experimental sources cannot
  silently enter production coverage.
- Feedback metrics: time to first useful result, task completion, false-positive
  disposition, incomplete-run rate and retry success. Pair analytics with
  interviews; do not collect analyst behaviour without notice and purpose.

## Remediation plan

1. **Make trust boundaries explicit (week 1):** implement health state,
   durable-storage capability state and the P0 disable rules. Add regression
   tests for each disabled/enabled transition.
2. **Fix navigation and terminology (week 1–2):** rename views, introduce URL
   state, add page headings and system status. Test keyboard and screen-reader
   behaviour before/after.
3. **Make long work controllable (week 2):** durable job IDs, cancellation,
   retry-failed-only and cost budgets. Verify server cleanup on disconnect.
4. **Harden persistence and access (week 2–4):** OIDC/RBAC, durable database,
   migrations, audit records, backups and retention enforcement.
5. **Close verification gaps continuously:** coverage ratchet, API contract
   canaries, browser automation, load tests and dependency dashboards.
6. **Validate with users:** run task-based tests with analysts at baseline and
   after the changes. Ship only improvements that reduce completion time,
   errors or confusion without weakening incomplete-coverage warnings.

## Definition of done for the next audit

- All offline suites and compilation pass.
- Coverage report identifies every unexecuted function and branch.
- Every enabled live provider has a recent successful canary or is visibly
  disabled/limited.
- Keyboard-only and automated accessibility checks pass at supported sizes and
  200% zoom.
- A user can start, understand, cancel, retry and recover a search without
  losing inputs.
- A saved result or disposition survives deployment restart, or its control is
  unavailable.
- Costs, data retention, provenance and incomplete coverage remain visible at
  the decision point.
