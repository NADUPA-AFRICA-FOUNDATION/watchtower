"""Offline checks for redirect expansion's security and evidence invariants."""

from datetime import datetime, timezone

import httpx
import pytest

from discovery.validate import (
    RedirectBudgetExceeded,
    RedirectExpander,
    SSRFError,
    canonicalize_url,
)


PUBLIC_DNS = lambda *_args, **_kwargs: [  # noqa: E731 - compact resolver stub
    (2, 1, 6, "", ("93.184.216.34", 443))
]


def _client(handler):
    return httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)


def test_redirect_hops_and_campaign_evidence():
    def handler(request):
        if request.url.host == "start.example":
            return httpx.Response(302, headers={
                "location": "https://end.example/offer?utm_source=mail&id=7"
            })
        return httpx.Response(200, text="done")

    expander = RedirectExpander(
        client=_client(handler), resolver=PUBLIC_DNS,
        clock=lambda: datetime(2026, 1, 2, tzinfo=timezone.utc),
    )
    result = expander.expand("https://start.example/x", source_promotion="search")

    assert result.requests_made == 2
    assert [hop.status_code for hop in result.hops] == [302, 200]
    assert result.hops[0].destination.endswith("utm_source=mail&id=7")
    assert all(hop.source_promotion == "search" for hop in result.hops)
    assert result.candidates[0].original_url.endswith("utm_source=mail&id=7")
    assert result.candidates[0].canonical_url == "https://end.example/offer?id=7"
    assert result.candidates[0].campaign_parameters == {"utm_source": ("mail",)}


def test_link_in_bio_outbounds_are_independent_candidates():
    html = """<a href='https://shop.example/a?fbclid=x'>shop</a>
              <a href='https://shop.example/a?fbclid=y'>duplicate</a>"""
    expander = RedirectExpander(
        client=_client(lambda _request: httpx.Response(200, text=html)),
        resolver=PUBLIC_DNS,
    )
    result = expander.expand("https://linktr.ee/person", source_promotion="trusted")

    assert len(result.candidates) == 1
    assert result.candidates[0].discovered_from == "https://linktr.ee/person"
    assert result.candidates[0].source_promotion is None
    assert result.candidates[0].canonical_url == "https://shop.example/a"


def test_private_dns_answer_is_rejected_before_request():
    requested = []
    expander = RedirectExpander(
        client=_client(lambda request: requested.append(request) or httpx.Response(200)),
        resolver=lambda *_args, **_kwargs: [(2, 1, 6, "", ("127.0.0.1", 443))],
    )
    with pytest.raises(SSRFError):
        expander.expand("https://public-looking.example")
    assert requested == []


def test_loop_and_redirect_budget_terminate_strictly():
    expander = RedirectExpander(
        client=_client(lambda request: httpx.Response(
            302, headers={"location": "https://b.example" if request.url.host ==
                          "a.example" else "https://a.example"})),
        resolver=PUBLIC_DNS, max_redirects=3,
    )
    result = expander.expand("https://a.example")
    assert result.termination_reason == "redirect_loop"
    assert result.requests_made == 2

    strict = RedirectExpander(
        client=_client(lambda _request: httpx.Response(
            302, headers={"location": "https://b.example"})),
        resolver=PUBLIC_DNS, max_redirects=0,
    )
    with pytest.raises(RedirectBudgetExceeded):
        strict.expand("https://a.example")


def test_canonicalization_normalizes_tracking_without_losing_identity_fields():
    assert canonicalize_url(
        "HTTPS://Example.COM:443/path?utm_campaign=sale&b=2&a=1#section"
    ) == "https://example.com/path?a=1&b=2"
