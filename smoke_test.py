"""Offline smoke test. No network, no API key. Proves the pipeline wiring works.

    python smoke_test.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from core import alerts
from core.clean import extract, truncate
from core.models import Item
from core.store import Store

SAMPLE_HTML = """
<html><head><title>Regulator fines bank over AML failings</title></head>
<body>
  <nav><a href="/">Home</a><a href="/news">News</a></nav>
  <article>
    <h1>Regulator fines bank over AML failings</h1>
    <p>The Central Bank of Kenya has imposed a penalty on a commercial bank
    after a review found weaknesses in its transaction monitoring and
    beneficial ownership verification controls.</p>
    <p>The review covered correspondent banking relationships across three
    markets and flagged gaps in escalation procedures.</p>
  </article>
  <footer>Copyright 2026. Subscribe to our newsletter!</footer>
</body></html>
"""

WATCHLIST = ["Central Bank of Kenya", "beneficial ownership",
             "correspondent banking", "nonexistent term"]


def check(label, condition):
    print(f"  {'PASS' if condition else 'FAIL'}  {label}")
    return condition


def main():
    ok = True
    db = Path("smoke.db")
    db.unlink(missing_ok=True)

    print("\nclean.extract")
    cleaned = extract(SAMPLE_HTML, "https://example.org/a")
    ok &= check("pulls the title", "AML failings" in cleaned["title"])
    ok &= check("pulls body text", "Central Bank of Kenya" in cleaned["text"])
    ok &= check("strips nav", "Home" not in cleaned["text"])
    ok &= check("strips footer", "Subscribe" not in cleaned["text"])
    ok &= check("truncate caps length", len(truncate("x " * 5000, 100)) < 130)

    print("\nmodels.Item")
    a = Item(url="https://a.com/1", source="rss:test", source_type="news",
             title=cleaned["title"], text=cleaned["text"])
    b = Item(url="https://b.com/9", source="rss:other", source_type="news",
             title=cleaned["title"], text=cleaned["text"])
    c = Item(url="https://c.com/3", source="rss:test", source_type="news",
             title="Unrelated sports result", text="A football match ended 2-1.")
    ok &= check("same story at two URLs shares a hash",
                a.content_hash == b.content_hash)
    ok &= check("different story differs", a.content_hash != c.content_hash)

    print("\nstore")
    s = Store(db)
    n1 = s.add([a, b, c])
    n2 = s.add([a, b, c])
    ok &= check(f"deduped syndicated copy on insert (got {n1}, want 2)", n1 == 2)
    ok &= check("re-running inserts nothing new", n2 == 0)
    ok &= check("seen_urls round-trips", (s.mark_seen(["https://a.com/1"], "t", "now")
                                          or s.is_seen("https://a.com/1")))
    ok &= check("stats report correctly", s.stats()["total"] == 2)

    print("\nsearch (FTS5)")
    hits = s.search("laundering OR monitoring")
    ok &= check("finds by body term", len(hits) == 1)
    ok &= check('phrase search works', len(s.search('"beneficial ownership"')) == 1)
    ok &= check("no false positives", len(s.search("volcano")) == 0)

    print("\nalerts")
    s.save_enrichment(a.content_hash, "Regulator penalised a bank.",
                      ["Central Bank of Kenya"], ["enforcement action"], 85)
    s.save_enrichment(c.content_hash, "A football result.", [], [], 4)
    selected = alerts.select(s, WATCHLIST, min_relevance=60)
    ok &= check("flags the relevant item only", len(selected) == 1)
    ok &= check("records both triggers",
                selected[0]["triggered_by"] == "keyword+model")
    ok &= check("whole-word matching avoids the decoy",
                "nonexistent term" not in selected[0]["keyword_hits"])
    ok &= check("caught all three real terms",
                len(selected[0]["keyword_hits"]) == 3)

    rendered = alerts.render(selected, brief="")
    ok &= check("digest renders", "1 new item(s) matched" in rendered)
    s.mark_alerted([x["content_hash"] for x in selected])
    ok &= check("alerted items don't repeat",
                len(alerts.select(s, WATCHLIST, 60)) == 0)

    s.close()
    db.unlink(missing_ok=True)

    print("\n" + ("ALL CHECKS PASSED" if ok else "SOME CHECKS FAILED") + "\n")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
