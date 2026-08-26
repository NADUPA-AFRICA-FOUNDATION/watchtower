from __future__ import annotations

import re


def normalized_aliases(brand: dict, override: str | None = None) -> list[str]:
    values = ([override] if override else []) + list(brand.get("aliases", []))
    if brand.get("name"):
        values.append(brand["name"])
    out: list[str] = []
    for value in values:
        alias = re.sub(r"\s+", " ", str(value).strip().lower())
        if alias and alias not in out:
            out.append(alias)
    return out


def domain_permutations(alias: str) -> list[str]:
    """Conservative CT search stems, not an exhaustive typosquat generator."""
    words = re.findall(r"[a-z0-9]+", alias.lower())
    if not words:
        return []
    forms = {"".join(words), "-".join(words)}
    if len(words) > 1:
        forms.update(words)
    # crt.sh substring searches shorter than three characters are extremely
    # noisy and can turn one brand into an effectively unbounded query.
    return sorted(form for form in forms if len(form) >= 3)


def certificate_queries(brand: dict, override: str | None = None) -> list[str]:
    queries: list[str] = []
    for alias in normalized_aliases(brand, override):
        for query in domain_permutations(alias):
            if query not in queries:
                queries.append(query)
    return queries
