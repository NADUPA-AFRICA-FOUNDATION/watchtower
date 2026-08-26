from __future__ import annotations
import json, urllib.parse, urllib.request
from discovery.providers.base import ProviderResult, ProviderState, credential

NAME="url_reputation"; ENV="URL_REPUTATION_API_KEY"; CREDENTIAL_REQUIREMENT=ENV
def collect(config: dict, urls: list[str], **_) -> ProviderResult:
    key=credential(config,NAME,ENV)
    if not key:return ProviderResult(NAME,ProviderState.SKIPPED,reason=f"missing {ENV}",credential_requirement=ENV)
    if not urls:return ProviderResult(NAME,ProviderState.SKIPPED,reason="no candidate URLs to enrich",credential_requirement=ENV)
    endpoint=config.get("discovery",{}).get("providers",{}).get(NAME,{}).get("endpoint")
    if not endpoint:return ProviderResult(NAME,ProviderState.FAILED,reason="URL reputation endpoint is not configured",credential_requirement=ENV)
    out=[]
    try:
        for url in urls:
            req=urllib.request.Request(endpoint+urllib.parse.quote(url,safe=""),headers={"Authorization":"Bearer "+key})
            with urllib.request.urlopen(req,timeout=15) as r:data=json.loads(r.read().decode())
            out.append({"url":url,"source":NAME,"reputation":data})
    except Exception as exc:return ProviderResult(NAME,ProviderState.FAILED,reason=str(exc),credential_requirement=ENV)
    return ProviderResult(NAME,ProviderState.SUCCESS,out,credential_requirement=ENV)
