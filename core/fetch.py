"""The fetch layer. This is where scrapers actually die, so it gets the care.

Three things that keep you unblocked and out of trouble, in order of importance:
  1. Respect robots.txt. Cheap to do, and it's the difference between
     "automated collection" and "unauthorised access" if anyone ever asks.
  2. Rate limit per domain, not globally. One domain hammered at 20 req/s gets
     you banned even if your overall rate looks polite.
  3. Identify yourself in the User-Agent with a contact address. Site owners
     who can reach you will email before they block you.
"""

from __future__ import annotations

import threading
import time
import urllib.robotparser
from dataclasses import dataclass
from urllib.parse import urlparse

import httpx


@dataclass
class FetchResult:
    url: str
    status: int
    html: str = ""
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.status == 200 and bool(self.html)


class Fetcher:
    def __init__(self, user_agent: str, delay: float = 2.0,
                 timeout: float = 20.0, obey_robots: bool = True,
                 transport=None):
        self.user_agent = user_agent
        self.delay = delay
        self.obey_robots = obey_robots
        self._last_hit: dict[str, float] = {}
        self._lock = threading.Lock()
        self.client = httpx.Client(
            headers={
                "User-Agent": user_agent,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-GB,en;q=0.9",
            },
            timeout=timeout,
            follow_redirects=True,
            transport=transport,          # tests inject a MockTransport here
        )
        self._robots: dict[str, urllib.robotparser.RobotFileParser | None] = {}

    # ---------- politeness ----------

    def _throttle(self, domain: str) -> None:
        """Per domain, not global. Thread-safe: sweeps fetch concurrently, and
        without the lock two threads can both read a stale timestamp and hit the
        same host at once."""
        while True:
            with self._lock:
                last = self._last_hit.get(domain, 0.0)
                wait = self.delay - (time.monotonic() - last)
                if wait <= 0:
                    self._last_hit[domain] = time.monotonic()
                    return
            time.sleep(wait)

    def allowed(self, url: str) -> bool:
        """Check robots.txt, fetched through our own client.

        Deliberately NOT urllib's RobotFileParser.read(): that opens its own
        connection, ignoring our user agent, timeout and any proxy, and it
        treats a 403 on robots.txt as 'disallow everything'. Behind a corporate
        proxy that silently kills every fetch you make.

        RFC 9309 status handling: 4xx means allow all, 5xx means the site is
        unwell so back off, and anything unreachable means allow.
        """
        if not self.obey_robots:
            return True
        parsed = urlparse(url)
        domain = parsed.netloc

        with self._lock:
            cached = domain in self._robots
        if not cached:
            rp: urllib.robotparser.RobotFileParser | None = None
            try:
                r = self.client.get(f"{parsed.scheme}://{domain}/robots.txt",
                                    timeout=10.0)
                if r.status_code == 200:
                    rp = urllib.robotparser.RobotFileParser()
                    rp.parse(r.text.splitlines())
                elif 500 <= r.status_code < 600:
                    rp = urllib.robotparser.RobotFileParser()
                    rp.disallow_all = True
                # 4xx and anything else: no usable rules, so allowed.
            except Exception:
                pass
            with self._lock:
                self._robots[domain] = rp

        with self._lock:
            rp = self._robots[domain]
        return True if rp is None else rp.can_fetch(self.user_agent, url)

    # ---------- fetching ----------

    def get(self, url: str, retries: int = 2, api: bool = False) -> FetchResult:
        """`api=True` skips the robots check. Use it only for the declared
        public API endpoints in core/sources.py.

        robots.txt governs crawlers indexing pages; it is not the access
        control mechanism for a documented JSON API you are calling as an
        intended consumer. Applying it to both was a category error that cost
        us every hit from Wikipedia and Google News: en.wikipedia.org/robots.txt
        carries `Disallow: /w/`, which is the path of the API Wikipedia
        publishes *for this purpose* and governs with its own rate-limit and
        user-agent policy. The backends returned [] and nobody saw why.

        Crawling arbitrary article bodies — sweep.py step 3, and adapters/ —
        keeps `api=False` and stays governed by obey_robots. That is genuine
        crawling and the protection belongs there.
        """
        if not api and not self.allowed(url):
            return FetchResult(url, 0, error="blocked by robots.txt")

        domain = urlparse(url).netloc
        backoff = 1.0

        for attempt in range(retries + 1):
            self._throttle(domain)
            try:
                r = self.client.get(url)
            except httpx.HTTPError as e:
                if attempt == retries:
                    return FetchResult(url, 0, error=f"{type(e).__name__}: {e}")
                time.sleep(backoff)
                backoff *= 2
                continue

            # 429/5xx are worth retrying; 403/404 are not.
            if r.status_code in (429, 500, 502, 503, 504) and attempt < retries:
                retry_after = r.headers.get("Retry-After")
                time.sleep(float(retry_after) if retry_after and retry_after.isdigit()
                           else backoff)
                backoff *= 2
                continue

            if r.status_code != 200:
                return FetchResult(url, r.status_code, error=f"HTTP {r.status_code}")
            return FetchResult(url, 200, html=r.text)

        return FetchResult(url, 0, error="exhausted retries")

    def close(self) -> None:
        self.client.close()
