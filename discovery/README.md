# Social discovery providers

These modules expose one shared `Candidate` contract without importing
Watchtower's storage-oriented `Item`. They use the same official endpoints,
authentication flows and response fields as the established adapters in
`core/sources.py`, while retaining discovery-specific evidence: the
promotional post/ad URL is distinct from any outbound landing URL.

An empty successful result means the API was searched and found no matches.
Missing configuration instead returns `ProviderResult(state="skipped")` with a
visible reason.

## Configuration and scope

* X: `X_BEARER_TOKEN` (official recent-search API).
* Reddit: `REDDIT_CLIENT_ID` and `REDDIT_CLIENT_SECRET` (official OAuth API).
* Bluesky: `BLUESKY_HANDLE` and `BLUESKY_APP_PASSWORD` (AT Protocol session).
* Mastodon: an explicitly selected instance; results are instance-dependent.
* Telegram: `TELEGRAM_PUBLIC_CHANNELS`, `TELEGRAM_SESSION`, and an injected,
  authorized client. Coverage is **only those configured public channels** and
  is never global Telegram coverage.
* Meta Ads: `META_ADS_API_APPROVED=true`, `META_ADS_ACCESS_TOKEN`, and
  `META_ADS_ACCOUNT_ID`. It remains skipped until every gate is present.
* TikTok: `TIKTOK_RESEARCH_API_APPROVED=true`,
  `TIKTOK_RESEARCH_ACCESS_TOKEN`, and `TIKTOK_RESEARCH_ACCOUNT_ID`. It remains
  skipped until every gate is present.

`SCAMSCAN_DISCOVERY_RETENTION_DAYS` defaults to 30 days. Each candidate records
collection and expiry timestamps so a persistence layer can enforce deletion
based on collection time. Creative text redacts incidental email addresses and
phone numbers; public account/advertiser IDs, content IDs, domains, timestamps,
engagement counts, and fraud-relevant links remain available for analysis.
