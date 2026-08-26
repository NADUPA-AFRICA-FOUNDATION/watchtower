from __future__ import annotations
import json, urllib.parse, urllib.request
from discovery.providers.base import ProviderResult, ProviderState, credential

NAME = "passive_dns"; ENV = "PASSIVE_DNS_API_KEY"
CREDENTIAL_REQUIREMENT = ENV

def collect(config: dict, domains: list[str], **_) -> ProviderResult:
    key = credential(config, NAME, ENV)
    if not key: return ProviderResult(NAME, ProviderState.SKIPPED, reason=f"missing {ENV}", credential_requirement=ENV)
    if not domains: return ProviderResult(NAME, ProviderState.SKIPPED, reason="no candidate domains to enrich", credential_requirement=ENV)
    endpoint = config.get("discovery", {}).get("providers", {}).get(NAME, {}).get("endpoint")
    if not endpoint: return ProviderResult(NAME, ProviderState.FAILED, reason="passive DNS endpoint is not configured", credential_requirement=ENV)
    found=[]
    try:
        for domain in domains:
            req=urllib.request.Request(endpoint+urllib.parse.quote(domain), headers={"Authorization":"Bearer "+key})
            with urllib.request.urlopen(req, timeout=15) as r: data=json.loads(r.read().decode())
            found.append({"domain":domain,"url":"https://"+domain,"source":NAME,"passive_dns":data})
    except Exception as exc: return ProviderResult(NAME, ProviderState.FAILED, reason=str(exc), credential_requirement=ENV)
    return ProviderResult(NAME, ProviderState.SUCCESS, found, credential_requirement=ENV)
