"""Orchestration for independent discovery providers."""

from dataclasses import dataclass
from typing import Any, Iterable, List, Mapping, Optional

from .models import Candidate, ProviderResult
from .provider import DiscoveryProvider, Progress, QueryPlan


@dataclass
class DiscoveryRun:
    """Collected candidates plus an auditable outcome for every provider."""

    candidates: List[Candidate]
    providers: List[ProviderResult]

    @property
    def provider_results(self) -> Mapping[str, ProviderResult]:
        """Outcomes keyed by provider name for status-oriented consumers."""
        return {result.provider: result for result in self.providers}


class DiscoveryEngine:
    def __init__(self, providers: Iterable[DiscoveryProvider]) -> None:
        self.providers = list(providers)

    def run(self, brand_profile: Mapping[str, Any], query_plan: QueryPlan,
            progress: Optional[Progress] = None,
            enabled: Optional[Iterable[str]] = None) -> DiscoveryRun:
        """Run all providers independently and deduplicate after collection."""
        progress = progress or (lambda event: None)
        enabled_names = set(enabled) if enabled is not None else None
        outcomes = []
        collected = []

        for provider in self.providers:
            configured = getattr(provider, "enabled", True)
            requested = (enabled_names is None or provider.name in enabled_names)
            if not configured or not requested:
                outcome = ProviderResult.skip(provider.name)
            else:
                try:
                    outcome = provider.search(brand_profile, query_plan, progress)
                    if not isinstance(outcome, ProviderResult):
                        raise TypeError("provider did not return ProviderResult")
                except Exception as exc:
                    outcome = ProviderResult.failure(
                        provider.name, f"{type(exc).__name__}: {exc}")
            outcomes.append(outcome)
            if outcome.searched:
                collected.extend(outcome.candidates)
            progress({"type": "provider_done", "provider": provider.name,
                      "searched": outcome.searched, "failed": outcome.failed,
                      "skipped": outcome.skipped,
                      "result_count": outcome.result_count,
                      "error": outcome.error})

        # Providers get the full query plan. Cross-provider/query dedupe happens
        # only here, after all sources have had an opportunity to contribute.
        unique = []
        seen = set()
        for candidate in collected:
            key = candidate.url.strip().lower()
            if key and key not in seen:
                seen.add(key)
                unique.append(candidate)
        return DiscoveryRun(candidates=unique, providers=outcomes)
