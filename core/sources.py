"""Keyword-searchable sources that need no API key and no scraping.

Every backend here takes a query string and returns list[Item]. All of them are
public APIs or published feeds, so there's no ToS grey area and nothing to
maintain when a site redesigns.

  gdelt      global news, all languages, 15-min lag, back to 2017
  google_news  broad news via the published RSS search endpoint
  wikipedia  entity background and disambiguation
  hackernews via Algolia's public API; good for tech and fintech chatter
  mastodon   public post search on any instance that allows it
  sec_edgar  US filings full-text, useful for company checks
  opensanctions  sanctions/PEP/watchlist matching (needs a free key)

Add a backend by writing one function with the same signature and registering
it in BACKENDS. Nothing else in the pipeline needs to change.
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timedelta, timezone
from urllib.parse import quote_plus, urlencode

import feedparser

from core.fetch import Fetcher
from core.models import Item


class SourceError(Exception):
    """A source could not be searched: blocked, timed out, 404, bad payload.

    The distinction this exists to protect: "we searched and found nothing" and
    "we could not look" are different answers, and for screening work the
    difference is the whole point. A backend that swallows a 429 and returns []
    renders identically to a clean result, and a clean result that is really a
    failed fetch is a false negative someone signs off on.
    """


class SourceSkipped(Exception):
    """A source was never attempted — not configured, no credentials.

    Deliberately not a SourceError. Nothing is broken and nothing needs
    fixing, but the source still wasn't searched, so it must not be reported
    as a zero either. See CLAUDE.md on degrading without keys.
    """


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


def _fail(res) -> None:
    """Turn a failed FetchResult into a SourceError carrying the real reason."""
    raise SourceError(res.error or f"HTTP {res.status}")


def _strip_tags(html: str) -> str:
    return re.sub(r"<[^>]+>", " ", html or "").replace("&nbsp;", " ").strip()


# ------------------------------------------------------------------ GDELT

def gdelt(query: str, fetcher: Fetcher, hours: int = 72,
          limit: int = 40) -> list[Item]:
    """Free, no key. Supports sourcecountry:, sourcelang:, domain: operators."""
    url = "https://api.gdeltproject.org/api/v2/doc/doc?" + urlencode({
        "query": query, "mode": "ArtList", "format": "json",
        "timespan": f"{hours}h", "maxrecords": min(limit, 250), "sort": "datedesc",
    })
    res = fetcher.get(url, api=True)
    if not res.ok:
        _fail(res)
    try:
        articles = json.loads(res.html).get("articles", [])
    except json.JSONDecodeError:
        raise SourceError("200 but the response body was not valid JSON")

    out = []
    for a in articles:
        if not a.get("url"):
            continue
        out.append(Item(
            url=a["url"], source="gdelt", source_type="news",
            title=(a.get("title") or "").strip(),
            published_at=a.get("seendate", ""),
            lang=a.get("language", ""),
            raw_meta={"domain": a.get("domain", ""),
                      "country": a.get("sourcecountry", "")},
        ))
    return out


# ------------------------------------------------------------ Google News

def google_news(query: str, fetcher: Fetcher, hours: int = 72,
                limit: int = 30) -> list[Item]:
    """Published RSS search endpoint. Broader recall than GDELT on local outlets."""
    when = f"{max(1, hours // 24)}d" if hours >= 24 else f"{hours}h"
    url = (f"https://news.google.com/rss/search?q={quote_plus(query)}"
           f"+when:{when}&hl=en&gl=KE&ceid=KE:en")
    res = fetcher.get(url, api=True)
    if not res.ok:
        _fail(res)

    out = []
    for e in feedparser.parse(res.html).entries[:limit]:
        if not e.get("link"):
            continue
        out.append(Item(
            url=e["link"], source="google_news", source_type="news",
            title=(e.get("title") or "").strip(),
            text=_strip_tags(e.get("summary", ""))[:1000],
            published_at=e.get("published", ""),
            raw_meta={"outlet": (e.get("source", {}) or {}).get("title", "")},
        ))
    return out


# -------------------------------------------------------------- Wikipedia

def wikipedia(query: str, fetcher: Fetcher, hours: int = 0,
              limit: int = 3) -> list[Item]:
    """Background context, not news. Answers 'who or what is this'."""
    url = "https://en.wikipedia.org/w/api.php?" + urlencode({
        "action": "query", "format": "json", "list": "search",
        "srsearch": query, "srlimit": limit,
    })
    res = fetcher.get(url, api=True)
    if not res.ok:
        _fail(res)
    try:
        hits = json.loads(res.html).get("query", {}).get("search", [])
    except json.JSONDecodeError:
        raise SourceError("200 but the response body was not valid JSON")

    out = []
    for h in hits:
        title = h.get("title", "")
        out.append(Item(
            url=f"https://en.wikipedia.org/wiki/{quote_plus(title.replace(' ', '_'))}",
            source="wikipedia", source_type="reference",
            title=title,
            text=_strip_tags(h.get("snippet", "")),
            published_at=h.get("timestamp", ""),
        ))
    return out


# ------------------------------------------------------------ Hacker News

def hackernews(query: str, fetcher: Fetcher, hours: int = 72,
               limit: int = 20) -> list[Item]:
    since = int((datetime.now(timezone.utc) - timedelta(hours=hours)).timestamp())
    url = "https://hn.algolia.com/api/v1/search_by_date?" + urlencode({
        "query": query, "hitsPerPage": limit,
        "numericFilters": f"created_at_i>{since}",
    })
    res = fetcher.get(url, api=True)
    if not res.ok:
        _fail(res)
    try:
        hits = json.loads(res.html).get("hits", [])
    except json.JSONDecodeError:
        raise SourceError("200 but the response body was not valid JSON")

    out = []
    for h in hits:
        link = h.get("url") or f"https://news.ycombinator.com/item?id={h.get('objectID')}"
        out.append(Item(
            url=link, source="hackernews", source_type="social",
            title=(h.get("title") or h.get("story_title") or "").strip(),
            text=_strip_tags(h.get("comment_text") or h.get("story_text") or "")[:2000],
            author=h.get("author", ""),
            published_at=h.get("created_at", ""),
            raw_meta={"points": h.get("points"), "comments": h.get("num_comments")},
        ))
    return out


# --------------------------------------------------------------- Mastodon

def mastodon(query: str, fetcher: Fetcher, hours: int = 72,
             limit: int = 20, instance: str = "mastodon.social") -> list[Item]:
    """Public post search. Open API, no key. Instances may rate-limit or opt out.

    This is the only genuinely open social network here. Instagram, TikTok,
    LinkedIn and X have no equivalent, which is why they're absent.
    """
    url = (f"https://{instance}/api/v2/search?"
           + urlencode({"q": query, "type": "statuses", "limit": min(limit, 40)}))
    res = fetcher.get(url, api=True)
    if not res.ok:
        _fail(res)
    try:
        statuses = json.loads(res.html).get("statuses", [])
    except json.JSONDecodeError:
        raise SourceError("200 but the response body was not valid JSON")

    out = []
    for s in statuses:
        acct = (s.get("account") or {}).get("acct", "")
        out.append(Item(
            url=s.get("url") or s.get("uri", ""), source=f"mastodon:{instance}",
            source_type="social",
            title=_strip_tags(s.get("content", ""))[:120],
            text=_strip_tags(s.get("content", "")),
            author=acct, published_at=s.get("created_at", ""),
            raw_meta={"reblogs": s.get("reblogs_count"),
                      "favourites": s.get("favourites_count")},
        ))
    return [i for i in out if i.url]


# -------------------------------------------------------------- SEC EDGAR

def sec_edgar(query: str, fetcher: Fetcher, hours: int = 0,
              limit: int = 15) -> list[Item]:
    """US filings full-text search. Free. Requires a real UA with contact info,
    which core/fetch.py already sends."""
    url = "https://efts.sec.gov/LATEST/search-index?" + urlencode(
        {"q": f'"{query}"', "forms": "", "hits": limit})
    res = fetcher.get(url, api=True)
    if not res.ok:
        url = "https://efts.sec.gov/LATEST/search-index?" + urlencode({"q": query})
        res = fetcher.get(url, api=True)
        if not res.ok:
            _fail(res)
    try:
        hits = json.loads(res.html).get("hits", {}).get("hits", [])
    except (json.JSONDecodeError, AttributeError):
        raise SourceError("200 but the response body was not the expected JSON")

    out = []
    for h in hits[:limit]:
        src = h.get("_source", {})
        cid = (h.get("_id") or "").split(":")[0].replace("-", "")
        out.append(Item(
            url=f"https://www.sec.gov/Archives/edgar/data/{cid}",
            source="sec_edgar", source_type="regulatory",
            title=" | ".join(filter(None, [src.get("display_names", [""])[0],
                                           src.get("file_type", "")])),
            published_at=src.get("file_date", ""),
            raw_meta={"form": src.get("root_form", "")},
        ))
    return out


# --------------------------------------------------------- OpenSanctions

def opensanctions(query: str, fetcher: Fetcher, hours: int = 0,
                  limit: int = 10) -> list[Item]:
    """Sanctions, PEP and watchlist matching. Needs a free OPENSANCTIONS_API_KEY.

    Without the key this raises SourceSkipped rather than returning [], so the
    sweep still completes but never reports an unsearched sanctions list as a
    clean one. That is the single most dangerous silent zero in the tool.
    """
    key = os.environ.get("OPENSANCTIONS_API_KEY")
    if not key:
        raise SourceSkipped("OPENSANCTIONS_API_KEY is not set")
    url = ("https://api.opensanctions.org/search/default?"
           + urlencode({"q": query, "limit": limit}))
    old = fetcher.client.headers.get("Authorization")
    fetcher.client.headers["Authorization"] = f"ApiKey {key}"
    res = fetcher.get(url, api=True)
    if old:
        fetcher.client.headers["Authorization"] = old
    else:
        fetcher.client.headers.pop("Authorization", None)
    if not res.ok:
        _fail(res)
    try:
        results = json.loads(res.html).get("results", [])
    except json.JSONDecodeError:
        raise SourceError("200 but the response body was not valid JSON")

    out = []
    for r in results:
        props = r.get("properties", {})
        topics = props.get("topics", [])
        out.append(Item(
            url=f"https://www.opensanctions.org/entities/{r.get('id', '')}/",
            source="opensanctions", source_type="watchlist",
            title=f"{r.get('caption', '')} ({r.get('schema', '')})",
            text=("Listed on: " + ", ".join(r.get("datasets", []))
                  + ". Topics: " + ", ".join(topics)
                  + ". Countries: " + ", ".join(props.get("country", []))),
            published_at=r.get("last_seen", ""),
            # A watchlist hit is never noise. Pre-scored so it can't be buried.
            relevance=95, enriched=True,
            raw_meta={"datasets": r.get("datasets", []), "topics": topics},
        ))
    return out


BACKENDS = {
    "gdelt": gdelt,
    "google_news": google_news,
    "wikipedia": wikipedia,
    "hackernews": hackernews,
    "mastodon": mastodon,
    "sec_edgar": sec_edgar,
    "opensanctions": opensanctions,
}

DEFAULT_BACKENDS = ["gdelt", "google_news", "wikipedia", "hackernews",
                    "mastodon", "opensanctions"]
