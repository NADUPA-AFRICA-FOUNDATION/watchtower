"""Bounded snscrape adapter for discovering public posts that link to sites.

snscrape is treated as an optional, capability-aware source: its absence or a
platform breakage never aborts DuckDuckGo discovery.  It runs as a subprocess
with an argument vector (never a shell), strict time/result budgets, and only
parses JSONL emitted by the public scraper CLI.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

URL_RE = re.compile(r"https?://[^\s<>\"'()]+", re.I)
PLATFORM_HOSTS = {
    "twitter.com",
    "x.com",
    "reddit.com",
    "www.reddit.com",
    "t.co",
}


def _external_urls(post):
    text = " ".join(
        str(post.get(key, ""))
        for key in ("rawContent", "content", "renderedContent", "title")
    )
    # snscrape also exposes expanded links in some platform-specific payloads.
    for link in post.get("links") or []:
        if isinstance(link, dict):
            text += " " + str(link.get("url") or link.get("href") or "")
        else:
            text += " " + str(link)
    urls = []
    for value in URL_RE.findall(text):
        url = value.rstrip(".,;:!?]}")
        host = (urlparse(url).hostname or "").lower()
        if host and host not in PLATFORM_HOSTS and url not in urls:
            urls.append(url)
    return urls


def _run_scraper(scraper, query, *, executable, max_results, timeout, runner):
    command = [executable, "--jsonl", "--max-results", str(max_results), scraper, query]
    completed = runner(
        command,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if completed.returncode:
        detail = (completed.stderr or "snscrape exited unsuccessfully").strip()
        return [], {
            "source": scraper,
            "status": "provider_error",
            "detail": detail[:300],
        }
    posts = []
    # Limit parsing separately from the process limit in case a broken CLI
    # ignores --max-results.
    for line in completed.stdout.splitlines()[:max_results]:
        try:
            value = json.loads(line)
        except (TypeError, json.JSONDecodeError):
            continue
        if isinstance(value, dict):
            posts.append(value)
    return posts, {"source": scraper, "status": "operational", "posts": len(posts)}


def discover_linked_sites(
    brand, config=None, *, runner=subprocess.run, which=shutil.which
):
    """Return linked-site candidates and transparent per-scraper coverage."""
    config = config or {}
    if not config.get("enabled", True):
        return {"results": [], "status": "disabled", "runs": []}
    executable = which(config.get("executable", "snscrape"))
    if not executable:
        return {
            "results": [],
            "status": "unavailable",
            "runs": [
                {
                    "source": "snscrape",
                    "status": "unavailable",
                    "detail": "snscrape executable is not installed",
                }
            ],
        }

    max_results = max(1, min(int(config.get("max_results_per_scraper", 20)), 100))
    timeout = max(3, min(float(config.get("timeout_seconds", 20)), 60))
    scrapers = tuple(config.get("scrapers", ("twitter-search", "reddit-search")))
    query = f'"{brand}"'
    outputs = []
    runs = []
    with ThreadPoolExecutor(max_workers=min(len(scrapers), 3) or 1) as pool:
        futures = {
            pool.submit(
                _run_scraper,
                scraper,
                query,
                executable=executable,
                max_results=max_results,
                timeout=timeout,
                runner=runner,
            ): scraper
            for scraper in scrapers
        }
        for future in as_completed(futures):
            scraper = futures[future]
            try:
                posts, run = future.result()
            except subprocess.TimeoutExpired:
                posts, run = [], {"source": scraper, "status": "timeout"}
            except OSError as exc:
                posts, run = (
                    [],
                    {
                        "source": scraper,
                        "status": "provider_error",
                        "detail": type(exc).__name__,
                    },
                )
            runs.append(run)
            for post in posts:
                post_url = str(post.get("url") or "")
                content = str(post.get("rawContent") or post.get("content") or "")
                for url in _external_urls(post):
                    outputs.append(
                        {
                            "url": url,
                            "title": f"Public post referencing {brand}",
                            "summary": content[:1000],
                            "source": f"snscrape:{scraper}",
                            "source_url": post_url,
                            "published_at": str(post.get("date") or ""),
                        }
                    )
    deduped = {result["url"]: result for result in outputs}
    statuses = {run["status"] for run in runs}
    status = (
        "operational"
        if statuses == {"operational"}
        else ("limited" if "operational" in statuses else "unavailable")
    )
    return {
        "results": list(deduped.values()),
        "status": status,
        "runs": sorted(runs, key=lambda run: run["source"]),
    }
