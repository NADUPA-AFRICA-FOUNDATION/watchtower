"""Reddit search through its official OAuth API."""

import base64
import os
from datetime import datetime, timezone
from urllib.parse import urlencode

from discovery.models import ProviderResult
from .common import candidate, json_body


def search(query, fetcher, *, limit=25, hours=72, retention=None, config=None):
    cfg = config or {}
    cid, secret = cfg.get("client_id") or os.getenv("REDDIT_CLIENT_ID"), cfg.get("client_secret") or os.getenv("REDDIT_CLIENT_SECRET")
    if not (cid and secret):
        return ProviderResult.skipped("reddit", "REDDIT_CLIENT_ID / REDDIT_CLIENT_SECRET are not configured")
    try:
        basic = base64.b64encode(f"{cid}:{secret}".encode()).decode()
        auth = json_body(fetcher.post("https://www.reddit.com/api/v1/access_token",
            data={"grant_type": "client_credentials"}, headers={"Authorization": f"Basic {basic}"}, api=True))
        window = "day" if hours <= 24 else "week" if hours <= 168 else "month"
        url = "https://oauth.reddit.com/search?" + urlencode({"q": query, "limit": min(limit, 100), "sort": "new", "t": window, "type": "link"})
        body = json_body(fetcher.get(url, api=True, headers={"Authorization": f"Bearer {auth['access_token']}"}))
        out = []
        for child in body.get("data", {}).get("children", [])[:limit]:
            d = child.get("data", {}); permalink = d.get("permalink")
            if not permalink: continue
            promo = "https://www.reddit.com" + permalink
            target = d.get("url_overridden_by_dest") or d.get("url")
            created = d.get("created_utc")
            out.append(candidate("reddit", promo, "\n".join(filter(None, [d.get("title"), d.get("selftext")])),
                urls=[target] if target and target != promo else [], account_id=d.get("author_fullname") or d.get("author"),
                content_id=d.get("name") or d.get("id"), published_at=datetime.fromtimestamp(created, timezone.utc).isoformat() if created else "",
                engagement={"score": d.get("score"), "comments": d.get("num_comments"), "upvote_ratio": d.get("upvote_ratio")},
                metadata={"subreddit": d.get("subreddit", "")}, retention=retention))
        return ProviderResult("reddit", candidates=out, coverage="Reddit OAuth search")
    except Exception as exc:
        return ProviderResult("reddit", "error", reason=str(exc))
