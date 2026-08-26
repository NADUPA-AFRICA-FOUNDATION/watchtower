from __future__ import annotations

import json
import ssl
import urllib.parse
import urllib.request

from discovery.providers.base import ProviderResult, ProviderState
from discovery.queries import certificate_queries

NAME = "certificate_transparency"
CREDENTIAL_REQUIREMENT = "none (public crt.sh endpoint)"
CT_SEARCH_URL = "https://crt.sh/?q=%25.{query}&output=json"


def collect(config: dict, brand_keyword: str | None = None,
            limit: int = 20, opener=None) -> ProviderResult:
    brand = config.get("brand", {})
    queries = certificate_queries(brand, brand_keyword)
    if not queries:
        return ProviderResult(NAME, ProviderState.SKIPPED,
                              reason="no normalized brand aliases produced a query",
                              credential_requirement=CREDENTIAL_REQUIREMENT)
    official = {str(d).lower().lstrip(".") for d in brand.get("official_domains", [])}
    candidates, seen, failures = [], set(), []
    opener = opener or urllib.request.urlopen
    context = ssl.create_default_context()
    for query in queries:
        try:
            request = urllib.request.Request(
                CT_SEARCH_URL.format(query=urllib.parse.quote(query)),
                headers={"User-Agent": "Watchtower/1.0"})
            response = opener(request, timeout=10, context=context)
            with response:
                rows = json.loads(response.read().decode("utf-8") or "[]")
        except Exception as exc:
            failures.append(f"{query}: {type(exc).__name__}: {exc}")
            continue
        for cert in rows:
            for value in str(cert.get("name_value", "")).splitlines():
                domain = value.strip().lower().removeprefix("*.").rstrip(".")
                if not domain or domain in seen or any(
                        domain == safe or domain.endswith("." + safe) for safe in official):
                    continue
                seen.add(domain)
                candidates.append({
                    "url": f"https://{domain}", "domain": domain,
                    "title": f"Certificate: {domain}",
                    "summary": f"Certificate name matched CT query {query}",
                    "source": NAME, "query": query,
                    "certificate_fingerprint": cert.get("sha256_fingerprint", ""),
                    "cert_info": {"issuer": cert.get("issuer_name", ""),
                                  "registered": cert.get("entry_timestamp", "")},
                })
                if len(candidates) >= limit:
                    return ProviderResult(NAME, ProviderState.SUCCESS, candidates,
                                          credential_requirement=CREDENTIAL_REQUIREMENT)
    if failures and not candidates:
        return ProviderResult(NAME, ProviderState.FAILED, reason="; ".join(failures[:3]),
                              credential_requirement=CREDENTIAL_REQUIREMENT)
    return ProviderResult(NAME, ProviderState.SUCCESS, candidates,
                          reason="; ".join(failures[:3]),
                          credential_requirement=CREDENTIAL_REQUIREMENT)
