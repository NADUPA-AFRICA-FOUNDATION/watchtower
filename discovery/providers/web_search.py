"""DuckDuckGo-backed web search provider."""

from typing import Any, Iterable, Mapping

from discovery.models import Candidate, ProviderResult
from discovery.provider import DiscoveryProvider, Progress, QueryPlan

try:
    from ddgs import DDGS
except ImportError:
    try:
        from duckduckgo_search import DDGS
    except ImportError:
        DDGS = None


class WebSearchError(RuntimeError):
    """DuckDuckGo could not execute a search."""


def search_duckduckgo(query: str, max_results: int = 10) -> list[dict[str, str]]:
    """Search DuckDuckGo and normalize the SDK's version-dependent response."""
    if DDGS is None:
        raise WebSearchError(
            "DuckDuckGo search is unavailable; install the 'ddgs' dependency")

    try:
        results = []
        with DDGS() as ddgs:
            for result in ddgs.text(query, max_results=max_results):
                if isinstance(result, dict):
                    results.append({
                        "title": result.get("title", ""),
                        "url": result.get("href", result.get("url", "")),
                        "summary": result.get("body", result.get("snippet", "")),
                        "source": "duckduckgo",
                        "query": query,
                    })
                elif isinstance(result, str):
                    results.append({
                        "title": "", "url": result, "summary": "",
                        "source": "duckduckgo", "query": query,
                    })
        return results
    except Exception as exc:
        raise WebSearchError(
            f"DuckDuckGo search failed for query {query!r}: {exc}") from exc


def _queries(query_plan: QueryPlan) -> Iterable[str]:
    if isinstance(query_plan, Mapping):
        value = query_plan.get("queries", query_plan.get("web_search", []))
    else:
        value = query_plan
    if isinstance(value, str):
        return [value]
    return value or []


class WebSearchProvider(DiscoveryProvider):
    """Collect web candidates without deduplicating across queries."""

    name = "web_search"

    def __init__(self, max_results: int = 10) -> None:
        self.max_results = max_results

    def search(self, brand_profile: Mapping[str, Any], query_plan: QueryPlan,
               progress: Progress) -> ProviderResult:
        del brand_profile  # Queries have already been tailored to the brand.
        candidates = []
        try:
            for query in _queries(query_plan):
                progress({"type": "provider_query", "provider": self.name,
                          "query": query})
                for result in search_duckduckgo(query, self.max_results):
                    url = result.get("url", "")
                    if not url:
                        continue
                    candidates.append(Candidate(
                        url=url,
                        source_url=url,
                        source=result.get("source", "duckduckgo"),
                        source_kind="web_search",
                        title=result.get("title", ""),
                        text=result.get("summary", ""),
                        query=result.get("query", query),
                        raw_meta=dict(result),
                    ))
        except Exception as exc:
            # Partial output cannot turn a provider failure into a clean search.
            return ProviderResult.failure(self.name, str(exc))
        return ProviderResult.success(self.name, candidates)
