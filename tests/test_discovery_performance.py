import time

import osint_discovery


def test_query_families_run_concurrently(monkeypatch):
    def slow_search(query, max_results=10):
        time.sleep(0.1)
        return [{"url": f"https://{query}.test"}]

    monkeypatch.setattr(osint_discovery, "search_duckduckgo", slow_search)
    osint_discovery._SEARCH_CACHE.clear()
    started = time.monotonic()
    outcomes = osint_discovery._search_queries_parallel(
        [f"brand-{index}" for index in range(5)], 1, workers=5, cache_ttl=0
    )
    elapsed = time.monotonic() - started

    assert len(outcomes) == 5
    # Serial execution takes about 0.5 seconds. Keep generous CI headroom while
    # still proving requests did not regress to sequential execution.
    assert elapsed < 0.35


def test_successful_search_results_are_reused(monkeypatch):
    calls = []

    def search(query, max_results=10):
        calls.append(query)
        return [{"url": "https://cached.test", "title": "cached"}]

    monkeypatch.setattr(osint_discovery, "search_duckduckgo", search)
    osint_discovery._SEARCH_CACHE.clear()

    first = osint_discovery._cached_search("same brand", 2, ttl_seconds=300)
    first[0]["title"] = "caller mutation"
    second = osint_discovery._cached_search("same brand", 2, ttl_seconds=300)

    assert calls == ["same brand"]
    assert second[0]["title"] == "cached"


def test_one_failed_query_does_not_delay_or_discard_siblings(monkeypatch):
    def mixed_search(query, max_results=10):
        if query == "broken":
            raise osint_discovery.DiscoveryError("provider timeout")
        return [{"url": f"https://{query}.test"}]

    monkeypatch.setattr(osint_discovery, "search_duckduckgo", mixed_search)
    osint_discovery._SEARCH_CACHE.clear()
    outcomes = osint_discovery._search_queries_parallel(
        ["first", "broken", "last"], 1, workers=3
    )

    assert [query for query, _, _ in outcomes] == ["first", "broken", "last"]
    assert outcomes[0][1] and outcomes[2][1]
    assert isinstance(outcomes[1][2], osint_discovery.DiscoveryError)
