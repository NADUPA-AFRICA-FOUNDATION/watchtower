"""Meta Ad Library provider, gated on explicit API approval and account scope."""

import os
from urllib.parse import urlencode
from discovery.models import ProviderResult
from .common import candidate, json_body, outbound_urls


def search(query, fetcher, *, limit=25, retention=None, config=None, **_):
    cfg = config or {}; token = cfg.get("access_token") or os.getenv("META_ADS_ACCESS_TOKEN")
    account = cfg.get("account_id") or os.getenv("META_ADS_ACCOUNT_ID")
    approved = cfg.get("approved", os.getenv("META_ADS_API_APPROVED", "").lower() in {"1", "true", "yes"})
    missing = []
    if not approved: missing.append("approved Meta Ad Library API access")
    if not token: missing.append("META_ADS_ACCESS_TOKEN")
    if not account: missing.append("META_ADS_ACCOUNT_ID")
    if missing: return ProviderResult.skipped("meta_ads", "missing " + ", ".join(missing))
    params = {"access_token": token, "search_terms": query, "ad_reached_countries": '["ALL"]', "limit": min(limit, 100),
              "fields": "id,ad_creation_time,ad_snapshot_url,ad_creative_bodies,ad_creative_link_captions,ad_creative_link_titles,page_id,page_name,impressions,spend"}
    try:
        body = json_body(fetcher.get("https://graph.facebook.com/v21.0/ads_archive?" + urlencode(params), api=True))
        out = []
        for ad in body.get("data", [])[:limit]:
            text = "\n".join((ad.get("ad_creative_bodies") or []) + (ad.get("ad_creative_link_titles") or []))
            shown = ad.get("ad_creative_link_captions") or []
            out.append(candidate("meta_ads", ad.get("ad_snapshot_url", ""), text, urls=outbound_urls(text), displayed=shown,
                account_id=ad.get("page_id"), content_id=ad.get("id"), published_at=ad.get("ad_creation_time", ""),
                engagement={"impressions": ad.get("impressions"), "spend": ad.get("spend")}, metadata={"configured_account_id": account}, retention=retention))
        return ProviderResult("meta_ads", candidates=out, coverage="Meta Ad Library API within the approved account scope")
    except Exception as exc: return ProviderResult("meta_ads", "error", reason=str(exc))
