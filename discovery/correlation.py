from __future__ import annotations

from collections import defaultdict
from typing import Any

# Infrastructure shared by unrelated customers is deliberately separated from
# operator-controlled identifiers. A shared IP/nameserver can support a case,
# but cannot create a malicious verdict by itself.
SUPPORTING = ("resolved_ips", "nameservers")
STRONG = ("certificate_fingerprints", "favicon_hashes", "analytics_ids",
          "payment_identifiers", "email_addresses", "telegram_handles",
          "page_fingerprints")

ALIASES = {
    "resolved_ips": ("ip_address", "resolved_ip"),
    "certificate_fingerprints": ("certificate_fingerprint",),
    "favicon_hashes": ("favicon_hash",),
    "analytics_ids": ("analytics_id", "shared_analytics_id"),
    "payment_identifiers": ("payment_identifier", "payment_references",
                            "mobile_money_numbers"),
    "email_addresses": ("email_address", "emails"),
    "telegram_handles": ("telegram_handle", "telegram_links"),
    "page_fingerprints": ("page_fingerprint", "dom_fingerprint", "html_hash"),
}


def _values(candidate: dict[str, Any], key: str) -> set[str]:
    values = []
    for candidate_key in (key, *ALIASES.get(key, ())):
        value = candidate.get(candidate_key, [])
        if isinstance(value, str):
            value = [value]
        if value:
            values.extend(value)
    return {str(item).strip().lower() for item in values if str(item).strip()}


def correlate(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Annotate candidates with explainable cross-candidate relationships."""
    indexes = {key: defaultdict(set) for key in SUPPORTING + STRONG}
    for index, candidate in enumerate(candidates):
        for key in indexes:
            for value in _values(candidate, key):
                indexes[key][value].add(index)

    output = []
    for index, candidate in enumerate(candidates):
        matches = []
        for key, values in indexes.items():
            for value in _values(candidate, key):
                peers = values[value] - {index}
                if peers:
                    matches.append({"signal": key, "value": value,
                                    "candidate_indexes": sorted(peers),
                                    "strength": "supporting" if key in SUPPORTING else "strong"})
        enriched = dict(candidate)
        enriched["correlations"] = matches
        enriched["correlation_summary"] = {
            "strong": sum(m["strength"] == "strong" for m in matches),
            "supporting": sum(m["strength"] == "supporting" for m in matches),
            "shared_infrastructure_only": bool(matches) and not any(
                m["strength"] == "strong" for m in matches),
        }
        output.append(enriched)
    return output
