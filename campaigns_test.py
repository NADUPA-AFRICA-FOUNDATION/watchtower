"""Offline tests for normalized, explainable campaign correlation."""
import tempfile
from pathlib import Path

from campaigns import CampaignStore, normalize_artifact


def test_campaign_correlation():
    path = Path(tempfile.mkdtemp()) / "campaigns.db"
    store = CampaignStore(str(path))
    try:
        assert normalize_artifact("domain", "EXAMPLE.COM.") == "example.com"
        assert normalize_artifact("url", "HTTPS://Example.com:443/a?b=2&a=1#x") == "https://example.com/a?a=1&b=2"
        first = store.observe("lead-a", [{"type": "phone", "value": "+254 712 345 678", "channel": "whatsapp"},
                                          {"type": "ip", "value": "192.0.2.1"}],
                              landing_url="https://one.example", promotional_source="Meta")
        second = store.observe("lead-b", [{"type": "phone", "value": "+254712345678", "channel": "whatsapp"}],
                               landing_url="https://two.example", promotional_source="WhatsApp")
        assert first == second
        detail = store.campaign(first)
        assert detail["edges"][0]["reason"] == "shared_whatsapp_number"
        assert len(detail["active_landing_sites"]) == 2

        # A shared cloud/CDN address is retained as context, not linkage.
        third = store.observe("lead-c", [{"type": "ip", "value": "192.0.2.1"}])
        assert third != first
        assert store.campaign(third)["edges"] == []

        # Stable IDs survive later observations and analyst workflow updates.
        assert store.observe("lead-a", [{"type": "page_fingerprint", "value": "AA:BB"}]) == first
        assert store.set_disposition(first, "confirmed", "same operator")
        assert store.campaign(first)["disposition"] == "confirmed"
    finally:
        store.close()
