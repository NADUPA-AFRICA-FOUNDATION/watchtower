from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]


def test_watchtower_yaml_has_no_merge_markers_and_keeps_discovery_limits():
    raw = (ROOT / "config.yaml").read_text(encoding="utf-8")
    assert not any(marker in raw for marker in ("<<<<<<<", "=======", ">>>>>>>"))

    config = yaml.safe_load(raw)
    discovery = config["discovery"]
    assert discovery["query_budget"] == 5
    assert discovery["search_concurrency"] == 5
    assert discovery["cache_ttl_seconds"] == 300
    assert discovery["snscrape"]["enabled"] is True
    assert discovery["snscrape"]["scrapers"] == [
        "twitter-search",
        "reddit-search",
    ]
    assert config["discovery"] == {
        "query_budget": 5,
        "search_concurrency": 5,
        "cache_ttl_seconds": 300,
    }
