from __future__ import annotations
import json, urllib.request
from discovery.providers.base import ProviderResult, ProviderState, credential

NAME="url_scanning"; ENV="URLSCAN_API_KEY"; CREDENTIAL_REQUIREMENT=ENV
def collect(config: dict, urls: list[str], **_) -> ProviderResult:
    settings=config.get("discovery",{}).get("providers",{}).get(NAME,{})
    key=credential(config,NAME,ENV)
    if not key:return ProviderResult(NAME,ProviderState.SKIPPED,reason=f"missing {ENV}",credential_requirement=ENV)
    if not urls:return ProviderResult(NAME,ProviderState.SKIPPED,reason="no candidate URLs to scan",credential_requirement=ENV)
    if not settings.get("approved",False):return ProviderResult(NAME,ProviderState.SKIPPED,reason="provider is not explicitly approved",credential_requirement=ENV)
    endpoint=settings.get("endpoint")
    if not endpoint:return ProviderResult(NAME,ProviderState.FAILED,reason="approved scanner endpoint is not configured",credential_requirement=ENV)
    out=[]
    try:
        for url in urls:
            req=urllib.request.Request(endpoint,data=json.dumps({"url":url,"visibility":settings.get("visibility","private")}).encode(),headers={"API-Key":key,"Content-Type":"application/json"})
            with urllib.request.urlopen(req,timeout=15) as r:data=json.loads(r.read().decode())
            out.append({"url":url,"source":NAME,"scan":data})
    except Exception as exc:return ProviderResult(NAME,ProviderState.FAILED,reason=str(exc),credential_requirement=ENV)
    return ProviderResult(NAME,ProviderState.SUCCESS,out,credential_requirement=ENV)
