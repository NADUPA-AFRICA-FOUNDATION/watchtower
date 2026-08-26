"""Coverage-contract tests for the synchronous discovery provider."""

import osint_discovery


CFG = {"brand": {"name": "Example", "aliases": []}}


def _run(search):
    original = (osint_discovery.generate_queries, osint_discovery.select_queries,
                osint_discovery.search_duckduckgo)
    try:
        osint_discovery.generate_queries = lambda *_args, **_kwargs: ["one", "two"]
        osint_discovery.select_queries = lambda queries, limit=8: list(queries)
        osint_discovery.search_duckduckgo = search
        return osint_discovery.discovery_report("example", 10, CFG)
    finally:
        (osint_discovery.generate_queries, osint_discovery.select_queries,
         osint_discovery.search_duckduckgo) = original


def test_completed_zero_is_distinct_from_failure():
    report = _run(lambda *_args, **_kwargs: [])
    assert report["complete"] is True
    assert report["providers"][0]["state"] == "zero_candidates"
    assert report["queries_searched"] == 2
    assert report["results_found"] == 0


def test_partial_rate_limit_preserves_incomplete_coverage():
    def search(query, **_kwargs):
        if query == "two":
            raise osint_discovery.DiscoveryError("429 rate limit")
        return []

    report = _run(search)
    assert report["complete"] is False
    assert report["providers_searched"] == ["duckduckgo"]
    assert report["providers_failed"] == ["duckduckgo"]
    assert report["query_counts"]["failed"] == 1
    assert report["provider_limitations"]["duckduckgo"]
