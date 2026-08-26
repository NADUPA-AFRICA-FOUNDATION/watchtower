import copy
import json
from pathlib import Path

import pytest

import osint_discovery
from osint_discovery import (
    DiscoveryError,
    _looks_relevant,
    _relevance_tokens,
    discover_and_score,
    generate_queries,
)
from scamscan import impersonation_score


ROOT = Path(__file__).resolve().parents[1]


def brand_profile():
    return json.loads((ROOT / "config.json").read_text(encoding="utf-8"))["brand"]


def test_competitors_are_not_mpesa_aliases():
    profile = brand_profile()
    aliases = {alias.casefold() for alias in profile["aliases"]}
    excluded = {brand.casefold() for brand in profile["excluded_brands"]}

    assert aliases.isdisjoint(excluded)
    assert impersonation_score("https://kcb.co.ke", profile)[0] == 0
    assert impersonation_score("https://equity-bank.example", profile)[0] == 0
    assert impersonation_score("https://mpesa-verify.example", profile)[0] > 0


def test_exclusion_wins_if_an_alias_is_accidentally_reintroduced():
    profile = copy.deepcopy(brand_profile())
    profile["aliases"].extend(["kcb", "equity bank"])

    assert impersonation_score("https://kcb.login.example", profile)[0] == 0
    assert impersonation_score("https://equity-bank.example", profile)[0] == 0

    queries = generate_queries({"brand": profile})
    assert not any('"kcb"' in query or '"equity bank"' in query for query in queries)


def test_cobranded_products_remain_in_scope():
    profile = brand_profile()

    assert "kcb mpesa" in profile["aliases"]
    assert impersonation_score("https://kcb-mpesa-login.example", profile)[0] > 0


def test_relevance_tokens_exclude_competitors():
    profile = brand_profile()
    tokens = _relevance_tokens({"brand": profile})

    assert "mpesa" in tokens
    assert "kcb mpesa" in tokens
    assert "kcb" not in tokens
    assert _looks_relevant(
        {"url": "https://offer.example", "title": "M-PESA verification"}, tokens
    )
    assert not _looks_relevant(
        {"url": "https://news.example", "title": "Unrelated weather report"},
        tokens,
    )


def test_total_provider_irrelevance_is_a_failure_not_a_clean_scan(monkeypatch):
    config = json.loads((ROOT / "config.json").read_text(encoding="utf-8"))

    def unrelated_search(query, max_results=10):
        return [
            {
                "url": "https://weather.example/today",
                "title": "Local weather",
                "summary": "Sunny with light winds",
                "source": "test-search",
            }
        ]

    monkeypatch.setattr(osint_discovery, "search_duckduckgo", unrelated_search)
    osint_discovery._SEARCH_CACHE.clear()

    with pytest.raises(DiscoveryError, match="not a clean scan"):
        discover_and_score("M-PESA", 1, config)
