"""One keyword in, a ranked set of findings out.

    findings = sweep("beneficial ownership Kenya", hours=72)

Pipeline: fan out across every backend -> dedupe on content hash -> fetch
article bodies concurrently -> clean -> score against the query with Claude ->
rank with source diversity -> roll up entities.

Runs fine with no API key at all. You lose scoring and summaries, and fall back
to keyword-overlap ranking, but you still get results.
"""

from __future__ import annotations

import re
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from concurrent.futures import TimeoutError as FuturesTimeout
from dataclasses import dataclass, field

from core.clean import extract, truncate
from core.enrich import Enricher
from core.fetch import Fetcher
from core.models import Item
from core.sources import BACKENDS, DEFAULT_BACKENDS, SourceError, SourceSkipped

STOPWORDS = {
    "the", "a", "an", "and", "or", "of", "in", "on", "for", "to", "at", "by",
    "with", "from", "is", "was", "are", "were", "be", "been", "as", "that",
    "this", "it", "its", "has", "have", "had", "not", "but", "they", "their",
}


@dataclass
class SweepResult:
    query: str
    items: list[Item] = field(default_factory=list)
    entities: list[tuple[str, int]] = field(default_factory=list)
    per_source: dict[str, int] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    enriched: bool = False
    # name -> reason. Sources that failed, and sources never attempted, kept
    # apart from each other and from a genuine zero. `per_source` says how many
    # hits; only these say whether the number can be trusted.
    failed: dict[str, str] = field(default_factory=dict)
    skipped: dict[str, str] = field(default_factory=dict)

    @property
    def strong(self) -> list[Item]:
        return [i for i in self.items if i.relevance >= 60]

    @property
    def complete(self) -> bool:
        """True when every requested source was actually searched. A zero-item
        sweep that is not complete must never be reported as 'nothing found'."""
        return not self.failed and not self.skipped


def _terms(query: str) -> list[str]:
    words = re.findall(r"[a-z0-9']+", query.lower())
    return [w for w in words if w not in STOPWORDS and len(w) > 2]


def _keyword_score(item: Item, terms: list[str]) -> int:
    """Fallback ranking when there's no API key. Crude but not useless:
    title matches count double, and coverage of the query matters more than
    raw frequency, so a doc mentioning every term beats one repeating a single
    term twenty times."""
    if not terms:
        return 0
    title = item.title.lower()
    body = item.text.lower()
    covered = sum(1 for t in terms if t in title or t in body)
    weighted = sum((2 if t in title else 0) + min(body.count(t), 5) for t in terms)
    return min(100, int((covered / len(terms)) * 60 + min(weighted, 20) * 2))


def _diversify(items: list[Item], cap_per_domain: int = 3) -> list[Item]:
    """Stop one prolific outlet burying everything else. Syndicated wire copy
    means a single story can occupy your entire top ten otherwise."""
    seen: Counter[str] = Counter()
    kept, overflow = [], []
    for item in items:
        domain = item.raw_meta.get("domain") or item.url.split("/")[2:3]
        domain = domain if isinstance(domain, str) else (domain[0] if domain else "?")
        if seen[domain] < cap_per_domain:
            seen[domain] += 1
            kept.append(item)
        else:
            overflow.append(item)
    return kept + overflow


def sweep(query: str, fetcher: Fetcher, hours: int = 72,
          backends: list[str] | None = None, limit: int = 40,
          fetch_bodies: bool = True, enricher: Enricher | None = None,
          max_enrich: int = 25, workers: int = 6, budget: float | None = None,
          progress=lambda event: None) -> SweepResult:
    """`progress` receives dicts, not strings, so callers can render them
    however they like: a CLI line, an SSE frame, a log record."""

    backends = backends or DEFAULT_BACKENDS
    result = SweepResult(query=query)
    terms = _terms(query)

    # `budget` exists for hosts that kill a request at a fixed wall clock —
    # serverless, mostly. Running out of time is reported through the same
    # `skipped` channel as a missing key, because it is the same fact: that
    # source was not searched, and the result must not read as if it were.
    deadline = (time.monotonic() + budget) if budget else None

    def time_left() -> float:
        return float("inf") if deadline is None else deadline - time.monotonic()

    # --- 1. fan out ---------------------------------------------------
    # Concurrent, not sequential: every backend is a different host, so there
    # is nothing to gain by serialising them and a lot to lose — one slow
    # source used to stall every lane behind it, which is why a live sweep
    # looked frozen for 58s and then finished all at once. Per-domain rate
    # limiting still holds because Fetcher._throttle checks and sets the
    # last-hit timestamp under one lock (see fetch_test in sweep_test.py).
    collected: list[Item] = []
    runnable = []
    for name in backends:
        fn = BACKENDS.get(name)
        if fn is None:
            result.errors.append(f"unknown backend: {name}")
            continue
        runnable.append((name, fn))

    def run_backend(name, fn):
        return name, fn(query, fetcher, hours=hours, limit=limit)

    # Not a `with` block: __exit__ calls shutdown(wait=True), which blocks until
    # the slowest backend finishes and would make the budget cosmetic — we'd
    # stop *waiting* on time and then get killed anyway. Shut down without
    # waiting and let the straggler die with the process.
    pool = ThreadPoolExecutor(max_workers=max(1, min(workers, len(runnable) or 1)))
    try:
        futures = {pool.submit(run_backend, n, f): n for n, f in runnable}
        try:
            # None, not inf: as_completed feeds this to Event.wait(), which
            # overflows on an infinite timeout rather than waiting forever.
            wait_for = None if deadline is None else max(0.0, time_left())
            done_iter = list(as_completed(futures, timeout=wait_for))
        except FuturesTimeout:
            done_iter = [f for f in futures if f.done()]
        for fut in futures:
            name = futures[fut]
            if fut not in done_iter:
                fut.cancel()
                result.skipped[name] = "exceeded the sweep time budget"
                result.per_source[name] = 0
                progress({"type": "source", "name": name, "count": 0,
                          "skipped": "exceeded the sweep time budget"})
                continue
            try:
                _, got = fut.result()
            except SourceSkipped as e:
                result.skipped[name] = str(e)
                result.per_source[name] = 0
                progress({"type": "source", "name": name, "count": 0,
                          "skipped": str(e)})
            except Exception as e:
                reason = str(e) if isinstance(e, SourceError) else f"{type(e).__name__}: {e}"
                result.failed[name] = reason
                result.errors.append(f"{name}: {reason}")
                result.per_source[name] = 0
                progress({"type": "source", "name": name, "count": 0,
                          "error": type(e).__name__, "reason": reason})
            else:
                collected.extend(got)
                result.per_source[name] = len(got)
                progress({"type": "source", "name": name, "count": len(got)})
    finally:
        pool.shutdown(wait=False, cancel_futures=True)

    # Completion order is nondeterministic; reports should not be. Restore the
    # order the caller asked for.
    result.per_source = {n: result.per_source[n] for n, _ in runnable
                         if n in result.per_source}
    collected.sort(key=lambda i: (i.source, i.url))

    if not collected:
        return result

    # --- 2. dedupe ----------------------------------------------------
    by_hash: dict[str, Item] = {}
    for item in collected:
        existing = by_hash.get(item.content_hash)
        if existing is None:
            by_hash[item.content_hash] = item
        elif len(item.text) > len(existing.text):
            by_hash[item.content_hash] = item      # keep the fuller copy
    deduped = list(by_hash.values())
    progress({"type": "stage", "stage": "dedupe",
              "before": len(collected), "after": len(deduped)})

    # --- 3. fetch bodies ----------------------------------------------
    needs_body = [i for i in deduped
                  if fetch_bodies and len(i.text) < 400
                  and i.source_type not in ("watchlist", "reference")]
    if needs_body and time_left() <= 1.0:
        result.skipped["article bodies"] = "exceeded the sweep time budget"
        needs_body = []
    if needs_body:
        progress({"type": "stage", "stage": "fetch", "count": len(needs_body)})

        def pull(item: Item) -> Item:
            res = fetcher.get(item.url, retries=1)
            if res.ok:
                c = extract(res.html, item.url)
                if len(c["text"]) > len(item.text):
                    item.text = c["text"]
                item.title = item.title or c["title"]
                item.author = item.author or c["author"]
                item.published_at = item.published_at or c["published_at"]
                item.lang = item.lang or c["lang"]
            else:
                item.raw_meta["fetch_error"] = res.error
            return item

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(pull, i) for i in needs_body]
            for f in as_completed(futures):
                try:
                    f.result()
                except Exception as e:
                    result.errors.append(f"body fetch: {type(e).__name__}: {e}")

    # --- 4. score ------------------------------------------------------
    # Cheap keyword pass over everything first, so the model only ever sees
    # the plausible candidates. This is what keeps a sweep affordable.
    for item in deduped:
        if not item.enriched:
            item.relevance = _keyword_score(item, terms)
    deduped.sort(key=lambda i: -i.relevance)

    if enricher and enricher.enabled:
        candidates = [i for i in deduped if not i.enriched][:max_enrich]
        progress({"type": "stage", "stage": "score", "count": len(candidates)})
        for item in candidates:
            out = enricher.enrich(item.title, truncate(item.text), focus=query)
            if out.get("skipped"):
                result.errors.append(out["skipped"])
                continue
            item.summary = out.get("summary", "")
            item.entities = out.get("entities", []) or []
            item.categories = out.get("categories", []) or []
            item.relevance = int(out.get("relevance", item.relevance))
            item.enriched = True
            progress({"type": "scored", "title": item.title[:80],
                      "relevance": item.relevance})
        result.enriched = True

    # --- 5. rank and roll up -------------------------------------------
    deduped.sort(key=lambda i: (-i.relevance, i.published_at), reverse=False)
    deduped.sort(key=lambda i: -i.relevance)
    result.items = _diversify(deduped)

    counts: Counter[str] = Counter()
    for item in result.items:
        for e in item.entities:
            if e.strip():
                counts[e.strip()] += 1
    result.entities = counts.most_common(15)

    return result
