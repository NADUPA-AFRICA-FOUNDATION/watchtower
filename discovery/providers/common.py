"""Parsing and privacy helpers shared by official provider adapters."""

from __future__ import annotations

import html
import json
import re
from urllib.parse import urlparse

from discovery.models import Candidate, RetentionConfig, retention_dates

URL_RE = re.compile(r"https?://[^\s<>\]\[\"']+", re.I)
TAG_RE = re.compile(r"<[^>]+>")
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
PHONE_RE = re.compile(r"(?<!\w)(?:\+?\d[\d .()\-]{7,}\d)(?!\w)")


def json_body(result):
    if not result.ok:
        raise RuntimeError(result.error or f"HTTP {result.status}")
    try:
        return json.loads(result.html)
    except (TypeError, json.JSONDecodeError) as exc:
        raise RuntimeError("official API returned invalid JSON") from exc


def clean_text(value: str) -> str:
    return html.unescape(TAG_RE.sub(" ", value or "")).replace("\u00a0", " ").strip()


def redact(value: str) -> str:
    """Remove incidental email/phone PII; public account IDs remain evidence."""
    return PHONE_RE.sub("[redacted-phone]", EMAIL_RE.sub("[redacted-email]", clean_text(value)))


def outbound_urls(text: str, entities=None) -> list[str]:
    urls = URL_RE.findall(text or "")
    for entity in entities or []:
        url = entity.get("expanded_url") or entity.get("expandedUrl") or entity.get("uri")
        if url:
            urls.append(url)
    return list(dict.fromkeys(u.rstrip(".,);!?") for u in urls if u))


def domains(urls: list[str], displayed=None) -> list[str]:
    values = [urlparse(u).hostname or "" for u in urls]
    # APIs commonly return display_url as ``example.com/path`` rather than a
    # URL. Keep only its host; paths and ad copy are not domains.
    values.extend((urlparse(v if "://" in v else "//" + v).hostname or "")
                  for v in (displayed or []) if v)
    return sorted({v.lower().removeprefix("www.").rstrip(".") for v in values if v})


def candidate(provider: str, promotional_url: str, text: str = "", *,
              urls=None, displayed=None, account_id="", content_id="",
              published_at="", engagement=None, metadata=None,
              retention: RetentionConfig | None = None) -> Candidate:
    landing = [u for u in (urls or outbound_urls(text)) if u != promotional_url]
    collected, expires = retention_dates(retention)
    return Candidate(provider, promotional_url, list(dict.fromkeys(landing)),
                     domains(landing, displayed), str(account_id or ""),
                     str(content_id or ""), published_at or "", redact(text),
                     engagement or {}, metadata or {}, collected, expires)
