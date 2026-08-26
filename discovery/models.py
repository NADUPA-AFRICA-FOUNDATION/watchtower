"""Persistence records for promotion-led discovery.

Promotions are evidence about *how* a site was found, not evidence about the
site's risk.  Keeping the platform post and landing page in separate records
prevents engagement counts and social-network hostnames from accidentally
entering the landing-site scorer.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Promotion:
    platform: str
    platform_record_id: str
    advertiser_id: str
    displayed_text: str = ""
    creative_metadata: dict[str, Any] = field(default_factory=dict)
    first_observed_at: str = field(default_factory=_now)
    last_observed_at: str = field(default_factory=_now)
    source_url: str = ""
    outbound_links: list[str] = field(default_factory=list)
    id: int | None = None

    def evidence(self) -> dict[str, Any]:
        """Return the attribution subset safe to expose alongside a score."""
        return {
            "platform": self.platform,
            "advertiser_id": self.advertiser_id,
            "displayed_text": self.displayed_text,
            "source_url": self.source_url,
            "first_observed_at": self.first_observed_at,
            "last_observed_at": self.last_observed_at,
        }


@dataclass
class LandingSite:
    canonical_url: str
    registrable_domain: str
    redirect_chain: list[str] = field(default_factory=list)
    final_url: str = ""
    fetch_status: int | str | None = None
    site_evidence: dict[str, Any] = field(default_factory=dict)
    id: int | None = None


@dataclass
class PromotionLanding:
    """Many-to-many edge; position preserves an observed link's ordering."""

    promotion_id: int
    landing_site_id: int
    position: int = 0


SCHEMA = """
CREATE TABLE IF NOT EXISTS promotions (
    id INTEGER PRIMARY KEY,
    platform TEXT NOT NULL,
    platform_record_id TEXT NOT NULL,
    advertiser_id TEXT NOT NULL,
    displayed_text TEXT NOT NULL DEFAULT '',
    creative_metadata TEXT NOT NULL DEFAULT '{}',
    first_observed_at TEXT NOT NULL,
    last_observed_at TEXT NOT NULL,
    source_url TEXT NOT NULL DEFAULT '',
    outbound_links TEXT NOT NULL DEFAULT '[]',
    UNIQUE(platform, platform_record_id)
);

CREATE TABLE IF NOT EXISTS landing_sites (
    id INTEGER PRIMARY KEY,
    canonical_url TEXT NOT NULL UNIQUE,
    registrable_domain TEXT NOT NULL,
    redirect_chain TEXT NOT NULL DEFAULT '[]',
    final_url TEXT NOT NULL DEFAULT '',
    fetch_status,
    site_evidence TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS promotion_landings (
    promotion_id INTEGER NOT NULL REFERENCES promotions(id) ON DELETE CASCADE,
    landing_site_id INTEGER NOT NULL REFERENCES landing_sites(id) ON DELETE CASCADE,
    position INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (promotion_id, landing_site_id)
);
CREATE INDEX IF NOT EXISTS idx_promotion_landings_site
    ON promotion_landings(landing_site_id);
"""


def create_schema(connection: sqlite3.Connection) -> None:
    """Install the promotion/landing tables on an existing SQLite database."""
    connection.execute("PRAGMA foreign_keys = ON")
    connection.executescript(SCHEMA)
    connection.commit()


def json_value(value: Any) -> str:
    """Stable JSON representation for callers persisting dataclass fields."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"))
