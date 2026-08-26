"""Instance-scoped Mastodon public status search."""

from urllib.parse import urlencode
from discovery.models import ProviderResult
from .common import candidate, clean_text, json_body, outbound_urls


def search(query, fetcher, *, limit=20, retention=None, config=None, **_):
    instance = (config or {}).get("instance", "mastodon.social").replace("https://", "").rstrip("/")
    try:
        body = json_body(fetcher.get(f"https://{instance}/api/v2/search?" + urlencode({"q": query, "type": "statuses", "limit": min(limit, 40)}), api=True))
        out = []
        for status in body.get("statuses", [])[:limit]:
            promo = status.get("url") or status.get("uri"); text = clean_text(status.get("content", ""))
            if not promo: continue
            out.append(candidate("mastodon", promo, text, urls=outbound_urls(status.get("content", "")), account_id=status.get("account", {}).get("id") or status.get("account", {}).get("acct"), content_id=status.get("id"), published_at=status.get("created_at", ""), engagement={"reblogs": status.get("reblogs_count"), "favourites": status.get("favourites_count"), "replies": status.get("replies_count")}, metadata={"instance": instance}, retention=retention))
        return ProviderResult("mastodon", candidates=out, coverage=f"Public statuses searchable by {instance}; not all Mastodon instances")
    except Exception as exc:
        return ProviderResult("mastodon", "error", reason=str(exc), coverage=f"Instance-scoped: {instance}")
