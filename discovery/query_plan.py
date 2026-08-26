"""Build auditable, family-budgeted brand discovery queries.

The planner is deliberately local and deterministic.  Model expansion is useful for
recall, but it cannot guarantee that an expensive lane (notably free-hosting searches)
will not crowd every other discovery technique out of a run.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Iterable, Mapping


EXACT_NAMES = "exact_names"
CREDENTIAL_BAIT = "credential_bait"
FINANCIAL_BAIT = "financial_bait"
PREVIOUS_ARTIFACTS = "previous_artifacts"
DOMAIN_PERMUTATIONS = "domain_permutations"
PLATFORM_SPECIFIC = "platform_specific"
CAMPAIGN_ARTIFACTS = "campaign_artifacts"

QUERY_FAMILIES = (
    EXACT_NAMES, CREDENTIAL_BAIT, FINANCIAL_BAIT, PREVIOUS_ARTIFACTS,
    DOMAIN_PERMUTATIONS, PLATFORM_SPECIFIC, CAMPAIGN_ARTIFACTS,
)


@dataclass(frozen=True)
class PlannedQuery:
    query: str
    query_family: str


def _strings(values: Iterable[object]) -> list[str]:
    return [str(v).strip() for v in values or [] if str(v).strip()]


def _artifacts(findings: Iterable[Mapping[str, object]]) -> list[str]:
    keys = ("phone_numbers", "phones", "paybills", "tills", "wallet_addresses",
            "wallets", "telegram_handles", "telegram")
    found: list[str] = []
    for item in findings or []:
        for key in keys:
            value = item.get(key)
            found.extend(_strings(value if isinstance(value, (list, tuple, set)) else [value]))
        text = " ".join(str(item.get(k, "")) for k in ("summary", "quoted_evidence"))
        found += re.findall(r"(?:\+?254|0)7\d{8}|@[A-Za-z][A-Za-z0-9_]{4,}|\b(?:paybill|till)\s*[:#-]?\s*\d{4,10}\b", text, re.I)
    return found


def _domain_variants(brand: Mapping[str, object]) -> list[str]:
    stems = []
    for name in [brand.get("name", ""), *_strings(brand.get("aliases", [])),
                 *_strings(brand.get("common_misspellings", []))]:
        stem = re.sub(r"[^a-z0-9]", "", str(name).lower())
        if stem and stem not in stems:
            stems.append(stem)
    variants = []
    substitutions = str.maketrans({"a": "а", "e": "е", "o": "о", "p": "р"})
    for stem in stems[:8]:
        variants.extend((f'"{stem}-login"', f'"{stem}-verify"', f'"{stem.translate(substitutions)}"'))
    return variants


def build_query_plan(brand: Mapping[str, object], budgets: Mapping[str, int],
                     previous_findings: Iterable[Mapping[str, object]] = (),
                     free_hosts: Iterable[str] = ()) -> list[PlannedQuery]:
    """Return queries capped independently by ``budgets[query_family]``.

    Missing budgets mean zero, making the cost policy explicit. Duplicate query text
    is removed globally, and the first (usually more fundamental) family owns it.
    """
    names = _strings([brand.get("name"), *brand.get("aliases", []),
                      *brand.get("products", [])])
    primary = names[0] if names else ""
    phrases = _strings(brand.get("campaign_phrases", []))
    families = {
        EXACT_NAMES: [f'"{name}"' for name in names],
        CREDENTIAL_BAIT: [f'"{name}" "{bait}"' for name in names[:5] for bait in
                          ("verify your account", "enter your PIN", "share your OTP", "account suspended")],
        FINANCIAL_BAIT: [f'"{primary}" "{bait}"' for bait in
                         ("instant loan", "claim your prize", "guaranteed returns", "job registration fee", "processing fee")],
        PREVIOUS_ARTIFACTS: [f'"{artifact}"' for artifact in _artifacts(previous_findings)],
        DOMAIN_PERMUTATIONS: _domain_variants(brand),
        PLATFORM_SPECIFIC: ([f'"{primary}" site:{host}' for host in _strings(free_hosts)] +
                            [f'"{primary}" site:t.me', f'"{primary}" site:facebook.com',
                             f'"{primary}" site:x.com', f'intitle:"{primary}" inurl:login']),
        CAMPAIGN_ARTIFACTS: [f'"{phrase}" -site:{domain}' for phrase in phrases
                             for domain in (_strings(brand.get("official_domains", []))[:1] or ["invalid"])],
    }
    plan, seen = [], set()
    for family in QUERY_FAMILIES:
        limit = max(0, int(budgets.get(family, 0)))
        if not limit:
            continue
        used = 0
        for query in families[family]:
            query = query.strip()
            if not query or query in seen:
                continue
            plan.append(PlannedQuery(query, family))
            seen.add(query)
            used += 1
            if used >= limit:
                break
    return plan
