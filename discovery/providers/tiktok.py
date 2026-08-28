"""TikTok Research API provider, disabled without approved scoped access."""

import os
from discovery.models import ProviderResult
from .common import candidate, json_body, outbound_urls


def search(query, fetcher, *, limit=25, retention=None, config=None, **_):
    cfg = config or {}; token = cfg.get("access_token") or os.getenv("TIKTOK_RESEARCH_ACCESS_TOKEN")
    account = cfg.get("account_id") or os.getenv("TIKTOK_RESEARCH_ACCOUNT_ID")
    approved = cfg.get("approved", os.getenv("TIKTOK_RESEARCH_API_APPROVED", "").lower() in {"1", "true", "yes"})
    missing = []
    if not approved: missing.append("approved TikTok Research API access")
    if not token: missing.append("TIKTOK_RESEARCH_ACCESS_TOKEN")
    if not account: missing.append("TIKTOK_RESEARCH_ACCOUNT_ID")
    if missing: return ProviderResult.skipped("tiktok", "missing " + ", ".join(missing))
    payload = {"query": {"and": [{"operation": "IN", "field_name": "keyword", "field_values": [query]}]},
               "fields": ["id", "username", "create_time", "video_description", "like_count", "comment_count", "share_count", "view_count", "voice_to_text"],
               "max_count": min(limit, 100)}
    try:
        body = json_body(fetcher.post("https://open.tiktokapis.com/v2/research/video/query/", json_body=payload, api=True, headers={"Authorization": f"Bearer {token}"}))
        out = []
        for video in body.get("data", {}).get("videos", [])[:limit]:
            username = video.get("username", ""); vid = video.get("id", ""); text = video.get("video_description", "")
            out.append(candidate("tiktok", f"https://www.tiktok.com/@{username}/video/{vid}", text, urls=outbound_urls(text),
                account_id=username or account, content_id=vid, published_at=str(video.get("create_time", "")),
                engagement={k: video.get(k) for k in ("like_count", "comment_count", "share_count", "view_count")}, retention=retention))
        return ProviderResult("tiktok", candidates=out, coverage="TikTok Research API within the approved account scope")
    except Exception as exc: return ProviderResult("tiktok", "error", reason=str(exc))
