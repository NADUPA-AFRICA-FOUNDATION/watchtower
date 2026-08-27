import json
import subprocess

import snscrape_discovery
import osint_discovery
import web.app as web_app


def completed(command, *, returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(command, returncode, stdout, stderr)


def test_missing_snscrape_degrades_without_aborting():
    result = snscrape_discovery.discover_linked_sites(
        "M-PESA", which=lambda executable: None
    )

    assert result["status"] == "unavailable"
    assert result["results"] == []
    assert result["runs"][0]["detail"] == "snscrape executable is not installed"


def test_public_posts_produce_deduplicated_linked_site_candidates():
    post = {
        "url": "https://twitter.com/example/status/1",
        "date": "2026-08-27T10:00:00Z",
        "rawContent": (
            "M-PESA promotion https://mpesa-offer.example/apply "
            "https://twitter.com/example"
        ),
    }

    def runner(command, **kwargs):
        assert command[:4] == ["/safe/snscrape", "--jsonl", "--max-results", "20"]
        assert kwargs["timeout"] == 20
        assert kwargs["check"] is False
        return completed(command, stdout=json.dumps(post) + "\n")

    result = snscrape_discovery.discover_linked_sites(
        "M-PESA", runner=runner, which=lambda executable: "/safe/snscrape"
    )

    assert result["status"] == "operational"
    assert len(result["results"]) == 1
    candidate = result["results"][0]
    assert candidate["url"] == "https://mpesa-offer.example/apply"
    assert candidate["source"].startswith("snscrape:")
    assert candidate["source_url"].endswith("/status/1")


def test_one_platform_failure_keeps_other_platform_results():
    def runner(command, **kwargs):
        scraper = command[-2]
        if scraper == "twitter-search":
            return completed(command, returncode=1, stderr="platform blocked")
        post = {
            "content": "Brand https://linked.example",
            "url": "https://reddit.com/r/x/1",
        }
        return completed(command, stdout=json.dumps(post))

    result = snscrape_discovery.discover_linked_sites(
        "Brand", runner=runner, which=lambda executable: "/safe/snscrape"
    )

    assert result["status"] == "limited"
    assert [item["url"] for item in result["results"]] == ["https://linked.example"]
    assert {run["status"] for run in result["runs"]} == {
        "operational",
        "provider_error",
    }


def test_discover_api_merges_socially_discovered_site(monkeypatch):
    with open("config.json", encoding="utf-8") as config_file:
        config = json.load(config_file)
    monkeypatch.setattr(web_app, "scamscan_config", lambda: config)
    monkeypatch.setattr(
        osint_discovery,
        "discover_and_score",
        lambda brand, limit, cfg, include_diagnostics: {
            "results": [],
            "coverage": {
                "queries_planned": 5,
                "queries_succeeded": 5,
                "queries_failed": 0,
                "raw_results": 0,
                "brand_relevant_results": 0,
            },
        },
    )
    monkeypatch.setattr(
        snscrape_discovery,
        "discover_linked_sites",
        lambda brand, cfg: {
            "status": "operational",
            "runs": [{"source": "reddit-search", "status": "operational"}],
            "results": [
                {
                    "url": "https://mpesa-social-offer.example",
                    "title": "Public post referencing M-PESA",
                    "summary": "MPESA activation fee",
                    "source": "snscrape:reddit-search",
                    "source_url": "https://reddit.com/r/scams/1",
                }
            ],
        },
    )

    response = web_app.discover_scams({"brand": "M-PESA", "limit": 5})

    assert response["count"] == 1
    assert response["results"][0]["source"] == "snscrape:reddit-search"
    assert response["coverage"]["snscrape_linked_sites"] == 1


def test_social_results_survive_web_search_failure(monkeypatch):
    with open("config.json", encoding="utf-8") as config_file:
        config = json.load(config_file)
    monkeypatch.setattr(web_app, "scamscan_config", lambda: config)
    monkeypatch.setattr(
        osint_discovery,
        "discover_and_score",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("DDG blocked")),
    )
    monkeypatch.setattr(
        snscrape_discovery,
        "discover_linked_sites",
        lambda brand, cfg: {
            "status": "operational",
            "runs": [{"source": "reddit-search", "status": "operational"}],
            "results": [
                {
                    "url": "https://mpesa-social-offer.example",
                    "title": "M-PESA public post",
                    "summary": "MPESA activation fee",
                    "source": "snscrape:reddit-search",
                }
            ],
        },
    )

    response = web_app.discover_scams({"brand": "M-PESA", "limit": 5})

    assert response["count"] == 1
    assert response["coverage"]["queries_succeeded"] == 0
    assert response["coverage"]["snscrape_status"] == "operational"
