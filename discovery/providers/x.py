"""X recent-search provider using only X's approved API."""

import os
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

from discovery.models import ProviderResult
from .common import candidate, json_body, outbound_urls


def search(query, fetcher, *, limit=20, hours=72, retention=None, config=None):
    token = (config or {}).get("bearer_token") or os.getenv("X_BEARER_TOKEN")
    if not token:
        return ProviderResult.skipped("x", "X_BEARER_TOKEN is not configured")
    params = {"query": query, "max_results": max(10, min(limit, 100)),
              "tweet.fields": "created_at,author_id,public_metrics,entities",
              "expansions": "author_id", "user.fields": "username"}
    if hours:
        start = datetime.now(timezone.utc) - timedelta(hours=min(hours, 24 * 7))
        params["start_time"] = start.isoformat(timespec="seconds").replace("+00:00", "Z")
    try:
        body = json_body(fetcher.get("https://api.x.com/2/tweets/search/recent?" + urlencode(params),
                                     api=True, headers={"Authorization": f"Bearer {token}"}))
        users = {u.get("id"): u for u in body.get("includes", {}).get("users", [])}
        out = []
        for post in body.get("data", [])[:limit]:
            user = users.get(post.get("author_id"), {})
            handle = user.get("username") or post.get("author_id", "")
            promo = f"https://x.com/{handle}/status/{post.get('id')}"
            entities = post.get("entities", {}).get("urls", [])
            shown = [e.get("display_url", "").split("/")[0] for e in entities]
            out.append(candidate("x", promo, post.get("text", ""),
                urls=outbound_urls(post.get("text", ""), entities), displayed=shown,
                account_id=post.get("author_id"), content_id=post.get("id"),
                published_at=post.get("created_at", ""),
                engagement=post.get("public_metrics", {}), retention=retention))
        return ProviderResult("x", candidates=out, coverage="X recent search (at most seven days)")
    except Exception as exc:
        return ProviderResult("x", "error", reason=str(exc))
