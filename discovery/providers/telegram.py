"""Seeded public-channel discovery using an authorized Telegram client.

This adapter only inspects explicitly configured public channels/seed links.
It is not, and must never be presented as, global Telegram coverage.
"""

import inspect
import os
import re

from discovery.models import ProviderResult
from .common import candidate, outbound_urls

COVERAGE = "Configured public Telegram channels only; not global Telegram coverage"


async def search_async(query, *, client=None, limit=25, retention=None, config=None, **_):
    cfg = config or {}
    seeds = cfg.get("channels") or cfg.get("seed_links") or [s.strip() for s in os.getenv("TELEGRAM_PUBLIC_CHANNELS", "").split(",") if s.strip()]
    session = cfg.get("session") or os.getenv("TELEGRAM_SESSION")
    if not seeds:
        return ProviderResult.skipped("telegram", "public channel usernames or seed links are required", COVERAGE)
    if client is None or not session:
        return ProviderResult.skipped("telegram", "an authorized Telegram client session is required", COVERAGE)
    authorized = client.is_user_authorized()
    if inspect.isawaitable(authorized): authorized = await authorized
    if not authorized:
        return ProviderResult.skipped("telegram", "the configured Telegram client session is not authorized", COVERAGE)
    out = []
    for seed in seeds:
        channel = re.sub(r"^https?://(?:t\.me|telegram\.me)/", "", seed).strip("/@")
        messages = client.iter_messages(channel, search=query, limit=limit)
        async for msg in messages:
            text = getattr(msg, "message", "") or ""; mid = getattr(msg, "id", "")
            promo = f"https://t.me/{channel}/{mid}"
            out.append(candidate("telegram", promo, text, urls=outbound_urls(text), account_id=channel,
                content_id=mid, published_at=getattr(getattr(msg, "date", None), "isoformat", lambda: "")(),
                engagement={"views": getattr(msg, "views", None), "forwards": getattr(msg, "forwards", None),
                            "replies": getattr(getattr(msg, "replies", None), "replies", None)}, retention=retention))
            if len(out) >= limit: break
        if len(out) >= limit: break
    return ProviderResult("telegram", candidates=out, coverage=COVERAGE)


def search(*args, **kwargs):
    """Return the coroutine explicitly; callers with Telegram clients are async."""
    return search_async(*args, **kwargs)
