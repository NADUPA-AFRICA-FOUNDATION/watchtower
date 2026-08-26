"""Promotion and landing-site model contract tests."""

import sqlite3

from core.store import Store
from discovery.models import LandingSite, Promotion


def main():
    promotion = Promotion("meta", "ad-1", "advertiser-9", source_url="https://social.example/ad/1")
    landing = LandingSite("https://offer.example/", "offer.example", final_url="https://offer.example/")
    assert promotion.evidence()["advertiser_id"] == "advertiser-9"
    assert landing.registrable_domain == "offer.example"

    store = Store(":memory:")
    tables = {row[0] for row in store.conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"promotions", "landing_sites", "promotion_landings"} <= tables

    store.conn.execute(
        "INSERT INTO promotions(platform, platform_record_id, advertiser_id, "
        "first_observed_at, last_observed_at) VALUES (?,?,?,?,?)",
        ("meta", "ad-1", "advertiser-9", "2026-01-01", "2026-01-02"))
    store.conn.executemany(
        "INSERT INTO landing_sites(canonical_url, registrable_domain) VALUES (?,?)",
        [("https://one.example", "one.example"),
         ("https://two.example", "two.example")])
    store.conn.executemany(
        "INSERT INTO promotion_landings VALUES (1,?,?)", [(1, 0), (2, 1)])
    assert store.conn.execute(
        "SELECT count(*) FROM promotion_landings WHERE promotion_id=1").fetchone()[0] == 2
    store.close()
    print("promotion/landing model checks passed")


if __name__ == "__main__":
    main()
