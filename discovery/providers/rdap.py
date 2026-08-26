from __future__ import annotations
import json, urllib.request
from discovery.providers.base import ProviderResult, ProviderState

NAME = "rdap"
CREDENTIAL_REQUIREMENT = "none (public RDAP bootstrap service)"

def collect(config: dict, domains: list[str], **_) -> ProviderResult:
    if not domains:
        return ProviderResult(NAME, ProviderState.SKIPPED,
                              reason="no candidate domains to enrich",
                              credential_requirement=CREDENTIAL_REQUIREMENT)
    candidates, errors = [], []
    for domain in domains:
        try:
            with urllib.request.urlopen("https://rdap.org/domain/" + domain, timeout=10) as r:
                data = json.loads(r.read().decode())
            candidates.append({"domain": domain, "url": "https://" + domain,
                "source": NAME, "registration": data,
                "nameservers": [n.get("ldhName", "").lower() for n in data.get("nameservers", [])]})
        except Exception as exc: errors.append(f"{domain}: {exc}")
    state = ProviderState.SUCCESS if candidates or not errors else ProviderState.FAILED
    return ProviderResult(NAME, state, candidates, "; ".join(errors[:3]), CREDENTIAL_REQUIREMENT)
