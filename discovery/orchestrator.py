from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import urlparse

from discovery.correlation import correlate
from discovery.providers.base import ProviderResult, ProviderState
from discovery.providers import certificate_transparency, passive_dns, rdap, url_reputation, url_scanning


@dataclass
class DiscoveryReport:
    candidates: list[dict[str, Any]] = field(default_factory=list)
    providers: dict[str, ProviderResult] = field(default_factory=dict)

    @property
    def complete(self) -> bool:
        return all(result.state is ProviderState.SUCCESS for result in self.providers.values())


def _domains(candidates: list[dict]) -> list[str]:
    values=[]
    for candidate in candidates:
        domain=candidate.get("domain") or urlparse(candidate.get("url", "")).hostname
        if domain and domain not in values: values.append(domain)
    return values


def run_discovery(config: dict, *, brand_keyword: str | None = None, limit: int = 20,
                  providers: list[str] | None = None,
                  seed_candidates: list[dict] | None = None,
                  progress: Callable[[dict], None] = lambda event: None) -> DiscoveryReport:
    """Run discovery/enrichment lanes through one visible failure-aware path."""
    requested=providers or ["certificate_transparency"]
    report=DiscoveryReport(candidates=list(seed_candidates or []))
    registry={"certificate_transparency":certificate_transparency.collect,
              "ct":certificate_transparency.collect,"rdap":rdap.collect,
              "passive_dns":passive_dns.collect,"url_reputation":url_reputation.collect,
              "url_scanning":url_scanning.collect}
    for name in requested:
        canonical="certificate_transparency" if name == "ct" else name
        fn=registry.get(name)
        if not fn:
            result=ProviderResult(canonical,ProviderState.FAILED,reason="unknown discovery provider")
        else:
            kwargs={"config":config,"brand_keyword":brand_keyword,"limit":limit,
                    "domains":_domains(report.candidates),
                    "urls":[c.get("url","") for c in report.candidates if c.get("url")]}
            try: result=fn(**kwargs)
            except Exception as exc:
                result=ProviderResult(canonical,ProviderState.FAILED,
                    reason=f"unhandled {type(exc).__name__}: {exc}")
        report.providers[canonical]=result
        if result.state is ProviderState.SUCCESS:
            known={c.get("url"): c for c in report.candidates}
            for candidate in result.candidates:
                current = known.get(candidate.get("url"))
                if current is not None:
                    current.update(candidate)
                else:
                    report.candidates.append(candidate)
                    known[candidate.get("url")] = candidate
        progress({"type":"provider","name":canonical,"state":result.state.value,
                  "count":len(result.candidates),"reason":result.reason,
                  "credential_requirement":result.credential_requirement})
    report.candidates=correlate(report.candidates)[:limit]
    return report
