"""Bluesky post search through AT Protocol session and appview APIs."""

import os
from urllib.parse import urlencode

from discovery.models import ProviderResult
from .common import candidate, json_body, outbound_urls


def search(query, fetcher, *, limit=25, retention=None, config=None, **_):
    cfg = config or {}; handle = cfg.get("handle") or os.getenv("BLUESKY_HANDLE"); password = cfg.get("app_password") or os.getenv("BLUESKY_APP_PASSWORD")
    if not (handle and password):
        return ProviderResult.skipped("bluesky", "BLUESKY_HANDLE / BLUESKY_APP_PASSWORD are not configured")
    try:
        session = json_body(fetcher.post("https://bsky.social/xrpc/com.atproto.server.createSession", json_body={"identifier": handle, "password": password}, api=True))
        url = "https://api.bsky.app/xrpc/app.bsky.feed.searchPosts?" + urlencode({"q": query, "limit": min(limit, 100), "sort": "latest"})
        body = json_body(fetcher.get(url, api=True, headers={"Authorization": f"Bearer {session['accessJwt']}"}))
        out = []
        for post in body.get("posts", [])[:limit]:
            rec = post.get("record", {}); author = post.get("author", {}); rkey = post.get("uri", "").rsplit("/", 1)[-1]
            facets = [f.get("features", []) for f in rec.get("facets", [])]
            entities = [e for group in facets for e in group]
            promo = f"https://bsky.app/profile/{author.get('handle')}/post/{rkey}"
            out.append(candidate("bluesky", promo, rec.get("text", ""), urls=outbound_urls(rec.get("text", ""), entities),
                account_id=author.get("did") or author.get("handle"), content_id=rkey, published_at=rec.get("createdAt", ""),
                engagement={"likes": post.get("likeCount"), "reposts": post.get("repostCount"), "replies": post.get("replyCount")}, retention=retention))
        return ProviderResult("bluesky", candidates=out, coverage="Bluesky AT Protocol post search")
    except Exception as exc:
        return ProviderResult("bluesky", "error", reason=str(exc))
