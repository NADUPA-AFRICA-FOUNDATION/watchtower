"""Shared provider contract (deliberately independent of ``core.models.Item``)."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any


@dataclass(frozen=True)
class RetentionConfig:
    """Retention applied when a candidate is collected, not when it was posted."""

    days: int = field(default_factory=lambda: int(os.getenv("SCAMSCAN_DISCOVERY_RETENTION_DAYS", "30")))

    def __post_init__(self) -> None:
        if self.days < 1:
            raise ValueError("discovery retention days must be positive")


@dataclass
class Candidate:
    provider: str
    promotional_url: str
    landing_urls: list[str] = field(default_factory=list)
    displayed_domains: list[str] = field(default_factory=list)
    account_id: str = ""
    content_id: str = ""
    published_at: str = ""
    creative_text: str = ""
    engagement: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    collected_at: str = ""
    expires_at: str = ""


@dataclass
class ProviderResult:
    provider: str
    state: str = "ok"  # ok, skipped, error
    candidates: list[Candidate] = field(default_factory=list)
    reason: str = ""
    coverage: str = ""

    @classmethod
    def skipped(cls, provider: str, reason: str, coverage: str = "") -> "ProviderResult":
        return cls(provider=provider, state="skipped", reason=reason, coverage=coverage)


def retention_dates(config: RetentionConfig | None = None) -> tuple[str, str]:
    now = datetime.now(timezone.utc)
    return now.isoformat(), (now + timedelta(days=(config or RetentionConfig()).days)).isoformat()
