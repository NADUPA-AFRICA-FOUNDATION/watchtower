"""Normalized artifacts and explainable, persistent campaign correlation."""

from __future__ import annotations

import hashlib
import ipaddress
import sqlite3
from datetime import datetime, timezone
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


ARTIFACT_TYPES = {
    "domain", "url", "phone", "paybill", "till", "wallet", "email",
    "social_handle", "advertiser_id", "certificate_fingerprint", "ip",
    "nameserver", "favicon_hash", "page_fingerprint",
}

# Infrastructure shared by unrelated tenants is useful context, but cannot be
# the sole basis for an edge. This deliberately includes IPs and nameservers:
# both commonly identify a cloud/CDN provider rather than an operator.
CONTEXT_ONLY_TYPES = {"ip", "nameserver"}

REASONS = {
    "domain": "shared_domain", "url": "shared_landing_url",
    "phone": "shared_phone_number", "paybill": "shared_paybill",
    "till": "shared_till_number", "wallet": "shared_wallet_address",
    "email": "shared_email_address", "social_handle": "shared_social_handle",
    "advertiser_id": "same_meta_advertiser",
    "certificate_fingerprint": "same_certificate_fingerprint",
    "favicon_hash": "same_favicon_hash",
    "page_fingerprint": "same_page_fingerprint",
}

SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS artifacts (
  id INTEGER PRIMARY KEY, type TEXT NOT NULL, normalized_value TEXT NOT NULL,
  display_value TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
  UNIQUE(type, normalized_value)
);
CREATE TABLE IF NOT EXISTS campaign_records (
  record_id TEXT PRIMARY KEY, landing_url TEXT, promotional_source TEXT,
  first_seen TEXT NOT NULL, last_seen TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS record_artifacts (
  record_id TEXT NOT NULL REFERENCES campaign_records(record_id) ON DELETE CASCADE,
  artifact_id INTEGER NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
  first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
  PRIMARY KEY(record_id, artifact_id)
);
CREATE TABLE IF NOT EXISTS campaigns (
  campaign_id TEXT PRIMARY KEY, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
  disposition TEXT NOT NULL DEFAULT 'unreviewed', analyst_note TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS campaign_members (
  campaign_id TEXT NOT NULL REFERENCES campaigns(campaign_id),
  record_id TEXT PRIMARY KEY REFERENCES campaign_records(record_id)
);
CREATE TABLE IF NOT EXISTS campaign_edges (
  left_record_id TEXT NOT NULL REFERENCES campaign_records(record_id),
  right_record_id TEXT NOT NULL REFERENCES campaign_records(record_id),
  artifact_id INTEGER NOT NULL REFERENCES artifacts(id), reason TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY(left_record_id, right_record_id, artifact_id)
);
CREATE INDEX IF NOT EXISTS idx_ra_artifact ON record_artifacts(artifact_id);
CREATE INDEX IF NOT EXISTS idx_members_campaign ON campaign_members(campaign_id);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_artifact(kind: str, value: str) -> str:
    """Return the canonical representation used for identity and matching."""
    kind = kind.strip().lower()
    if kind not in ARTIFACT_TYPES:
        raise ValueError(f"unsupported artifact type: {kind}")
    value = str(value).strip()
    if not value:
        raise ValueError("artifact value cannot be empty")
    if kind in {"domain", "nameserver"}:
        return value.rstrip(".").lower().encode("idna").decode("ascii")
    if kind == "url":
        raw = value if "://" in value else "https://" + value
        p = urlsplit(raw)
        host = (p.hostname or "").rstrip(".").lower().encode("idna").decode("ascii")
        if not host:
            raise ValueError("URL must contain a host")
        port = p.port
        netloc = host if not port or (p.scheme.lower(), port) in {("http", 80), ("https", 443)} else f"{host}:{port}"
        path = p.path or "/"
        query = urlencode(sorted(parse_qsl(p.query, keep_blank_values=True)))
        return urlunsplit((p.scheme.lower(), netloc, path, query, ""))
    if kind in {"phone", "paybill", "till"}:
        digits = "".join(c for c in value if c.isdigit())
        if not digits:
            raise ValueError(f"{kind} must contain digits")
        return ("+" if kind == "phone" and value.lstrip().startswith("+") else "") + digits
    if kind == "email":
        local, separator, domain = value.rpartition("@")
        if not separator or not local or not domain:
            raise ValueError("invalid email address")
        return f"{local.lower()}@{normalize_artifact('domain', domain)}"
    if kind == "ip":
        return ipaddress.ip_address(value).compressed
    if kind in {"certificate_fingerprint", "favicon_hash", "page_fingerprint"}:
        compact = "".join(c for c in value.lower() if c.isalnum())
        if not compact:
            raise ValueError(f"invalid {kind}")
        return compact
    if kind == "social_handle":
        return value.lstrip("@").lower()
    if kind == "advertiser_id":
        return value.lower().removeprefix("act_")
    return value  # wallet addresses can be case-sensitive/checksummed


class CampaignStore:
    """Store observations and correlate only on explicit shared artifacts."""

    def __init__(self, path: str):
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)

    def close(self):
        self.conn.close()

    def observe(self, record_id: str, artifacts: list[dict], *, landing_url: str = "",
                promotional_source: str = "", seen_at: str | None = None) -> str:
        seen = seen_at or _now()
        record_id = str(record_id).strip()
        if not record_id:
            raise ValueError("record_id is required")
        with self.conn:
            self.conn.execute(
                "INSERT INTO campaign_records VALUES (?,?,?,?,?) ON CONFLICT(record_id) DO UPDATE SET "
                "landing_url=COALESCE(NULLIF(excluded.landing_url,''),landing_url), "
                "promotional_source=COALESCE(NULLIF(excluded.promotional_source,''),promotional_source), "
                "last_seen=MAX(last_seen,excluded.last_seen)",
                (record_id, landing_url, promotional_source, seen, seen))
            artifact_ids = []
            for item in artifacts:
                kind, raw = str(item["type"]).lower(), str(item["value"])
                normalized = normalize_artifact(kind, raw)
                self.conn.execute(
                    "INSERT INTO artifacts(type,normalized_value,display_value,first_seen,last_seen) VALUES(?,?,?,?,?) "
                    "ON CONFLICT(type,normalized_value) DO UPDATE SET last_seen=MAX(last_seen,excluded.last_seen)",
                    (kind, normalized, raw, seen, seen))
                aid = self.conn.execute("SELECT id FROM artifacts WHERE type=? AND normalized_value=?",
                                        (kind, normalized)).fetchone()[0]
                reason = REASONS.get(kind)
                if kind == "phone" and str(item.get("channel", "")).lower() == "whatsapp":
                    reason = "shared_whatsapp_number"
                artifact_ids.append((aid, kind, reason))
                self.conn.execute("INSERT INTO record_artifacts VALUES(?,?,?,?) ON CONFLICT(record_id,artifact_id) "
                                  "DO UPDATE SET last_seen=MAX(last_seen,excluded.last_seen)",
                                  (record_id, aid, seen, seen))
            self._correlate(record_id, artifact_ids, seen)
        return self.conn.execute("SELECT campaign_id FROM campaign_members WHERE record_id=?",
                                 (record_id,)).fetchone()[0]

    def _correlate(self, record_id, artifact_ids, seen):
        existing = self.conn.execute("SELECT campaign_id FROM campaign_members WHERE record_id=?", (record_id,)).fetchone()
        candidate_campaigns = {existing[0]} if existing else set()
        edges = []
        for aid, kind, reason in artifact_ids:
            if kind in CONTEXT_ONLY_TYPES:
                continue
            for row in self.conn.execute(
                "SELECT ra.record_id,cm.campaign_id FROM record_artifacts ra "
                "LEFT JOIN campaign_members cm ON cm.record_id=ra.record_id "
                "WHERE ra.artifact_id=? AND ra.record_id<>?", (aid, record_id)):
                left, right = sorted((record_id, row["record_id"]))
                edges.append((left, right, aid, reason, seen))
                if row["campaign_id"]:
                    candidate_campaigns.add(row["campaign_id"])
        if candidate_campaigns:
            campaign_id = min(candidate_campaigns)
        else:
            # Derived once from the first member, then persisted; later observations
            # and artifact changes cannot rename a campaign.
            campaign_id = "cmp_" + hashlib.sha256(record_id.encode()).hexdigest()[:16]
            self.conn.execute("INSERT OR IGNORE INTO campaigns VALUES(?,?,?,'unreviewed','')",
                              (campaign_id, seen, seen))
        for obsolete in candidate_campaigns - {campaign_id}:
            self.conn.execute("UPDATE OR REPLACE campaign_members SET campaign_id=? WHERE campaign_id=?",
                              (campaign_id, obsolete))
            self.conn.execute("DELETE FROM campaigns WHERE campaign_id=?", (obsolete,))
        self.conn.execute("INSERT OR REPLACE INTO campaign_members VALUES(?,?)", (campaign_id, record_id))
        self.conn.executemany("INSERT OR IGNORE INTO campaign_edges VALUES(?,?,?,?,?)", edges)
        self.conn.execute("UPDATE campaigns SET first_seen=MIN(first_seen,?),last_seen=MAX(last_seen,?) WHERE campaign_id=?",
                          (seen, seen, campaign_id))

    def set_disposition(self, campaign_id: str, disposition: str, note: str = ""):
        allowed = {"unreviewed", "monitoring", "confirmed", "false_positive", "closed"}
        if disposition not in allowed:
            raise ValueError(f"disposition must be one of {sorted(allowed)}")
        with self.conn:
            cur = self.conn.execute("UPDATE campaigns SET disposition=?,analyst_note=? WHERE campaign_id=?",
                                    (disposition, note[:2000], campaign_id))
        return bool(cur.rowcount)

    def campaigns(self) -> list[dict]:
        return [self.campaign(row[0]) for row in self.conn.execute(
            "SELECT campaign_id FROM campaigns ORDER BY last_seen DESC")]

    def campaign(self, campaign_id: str) -> dict | None:
        row = self.conn.execute("SELECT * FROM campaigns WHERE campaign_id=?", (campaign_id,)).fetchone()
        if not row:
            return None
        records = self.conn.execute(
            "SELECT r.* FROM campaign_records r JOIN campaign_members m USING(record_id) WHERE m.campaign_id=?",
            (campaign_id,)).fetchall()
        artifacts = self.conn.execute(
            "SELECT a.* FROM artifacts a JOIN record_artifacts ra ON ra.artifact_id=a.id "
            "JOIN campaign_members m ON m.record_id=ra.record_id WHERE m.campaign_id=? "
            "GROUP BY a.id HAVING COUNT(DISTINCT ra.record_id)>1 ORDER BY a.type,a.normalized_value",
            (campaign_id,)).fetchall()
        edges = self.conn.execute(
            "SELECT e.left_record_id,e.right_record_id,e.reason,a.type,a.normalized_value AS artifact "
            "FROM campaign_edges e JOIN artifacts a ON a.id=e.artifact_id "
            "JOIN campaign_members m ON m.record_id=e.left_record_id WHERE m.campaign_id=? ORDER BY e.created_at",
            (campaign_id,)).fetchall()
        return {**dict(row), "active_landing_sites": sorted({r["landing_url"] for r in records if r["landing_url"]}),
                "promotional_sources": sorted({r["promotional_source"] for r in records if r["promotional_source"]}),
                "shared_artifacts": [dict(a) for a in artifacts], "edges": [dict(e) for e in edges],
                "record_count": len(records)}
