"""Safely expand redirecting discovery URLs.

Redirects are deliberately followed in application code rather than delegated
to the HTTP client.  That makes every network boundary visible and, more
importantly, ensures an attacker cannot use a redirect to bypass the SSRF
policy.  DNS is checked immediately before each request and *all* returned
addresses must be globally routable.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from html.parser import HTMLParser
from typing import Callable, Iterable, Mapping, Optional
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

import httpx


REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
TRACKING_PARAMETERS = frozenset({
    "_hsenc", "_hsmi", "dclid", "fbclid", "gclid", "gbraid", "igshid",
    "mc_cid", "mc_eid", "msclkid", "ref", "ref_src", "srsltid",
    "twclid", "vero_conv", "vero_id", "wbraid", "yclid",
})
CAMPAIGN_PREFIXES = ("utm_",)
LINK_IN_BIO_HOSTS = frozenset({
    "beacons.ai", "bio.link", "campsite.bio", "hoo.be", "link.bio",
    "linkin.bio", "linktr.ee", "lnk.bio", "msha.ke", "solo.to",
    "stan.store", "tap.bio", "withkoji.com",
})


class ExpansionError(RuntimeError):
    """Base class for a safely terminated expansion."""


class SSRFError(ExpansionError):
    """The target is not safe to request from the public internet."""


class RedirectBudgetExceeded(ExpansionError):
    """The redirect chain exceeded its configured maximum."""


class RequestBudgetExceeded(ExpansionError):
    """The expansion exhausted its total network request allowance."""


@dataclass(frozen=True)
class RedirectHop:
    status_code: int
    timestamp: str
    source_promotion: str
    destination: str
    source: str


@dataclass(frozen=True)
class Candidate:
    """A destination with both its dedupe identity and untouched evidence."""

    url: str
    canonical_url: str
    original_url: str
    campaign_parameters: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    discovered_from: Optional[str] = None
    source_promotion: Optional[str] = None


@dataclass
class ExpansionResult:
    original_url: str
    hops: list[RedirectHop] = field(default_factory=list)
    candidates: list[Candidate] = field(default_factory=list)
    requests_made: int = 0
    termination_reason: Optional[str] = None


def _is_tracking_parameter(name: str) -> bool:
    lower = name.lower()
    return lower in TRACKING_PARAMETERS or lower.startswith(CAMPAIGN_PREFIXES)


def campaign_parameters(url: str) -> dict[str, tuple[str, ...]]:
    """Return tracking/campaign values without losing repeated parameters."""
    found: dict[str, list[str]] = {}
    for key, value in parse_qsl(urlsplit(url).query, keep_blank_values=True):
        if _is_tracking_parameter(key):
            found.setdefault(key, []).append(value)
    return {key: tuple(values) for key, values in found.items()}


def canonicalize_url(url: str) -> str:
    """Build a stable dedupe URL while retaining meaningful query fields.

    The caller must retain ``url`` separately as evidence.  Fragments and
    marketing parameters do not identify a different network resource.
    """
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower().rstrip(".")
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        pass
    port = parts.port
    if port and not ((scheme == "http" and port == 80) or
                     (scheme == "https" and port == 443)):
        authority = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
    else:
        authority = f"[{host}]" if ":" in host else host
    query = [(key, value) for key, value in
             parse_qsl(parts.query, keep_blank_values=True)
             if not _is_tracking_parameter(key)]
    query.sort()
    return urlunsplit((scheme, authority, parts.path or "/", urlencode(query), ""))


def _public_address(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError:
        return False
    # is_global excludes loopback, private, link-local, multicast, reserved and
    # unspecified ranges (including IPv4-mapped private IPv6 addresses).
    return address.is_global


class _Links(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.urls: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        if tag.lower() != "a":
            return
        href = dict(attrs).get("href")
        if href:
            self.urls.append(href.strip())


class RedirectExpander:
    """Expand one URL under explicit redirect and total-request budgets."""

    def __init__(
        self,
        *,
        client: Optional[httpx.Client] = None,
        resolver: Optional[Callable[..., Iterable[object]]] = None,
        max_redirects: int = 5,
        max_requests: int = 7,
        timeout: float = 10.0,
        link_in_bio_hosts: Iterable[str] = LINK_IN_BIO_HOSTS,
        clock: Optional[Callable[[], datetime]] = None,
    ) -> None:
        if max_redirects < 0 or max_requests < 1:
            raise ValueError("budgets must allow at least one request")
        self.max_redirects = max_redirects
        self.max_requests = max_requests
        self.timeout = timeout
        self.client = client or httpx.Client(follow_redirects=False, timeout=timeout)
        self.resolver = resolver or socket.getaddrinfo
        self.link_in_bio_hosts = frozenset(h.lower().rstrip(".") for h in link_in_bio_hosts)
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    @staticmethod
    def _validate_url(url: str) -> tuple[str, int]:
        try:
            parts = urlsplit(url)
            port = parts.port
        except ValueError as exc:
            raise SSRFError(f"invalid target URL: {exc}") from exc
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise SSRFError("only absolute HTTP(S) targets are allowed")
        if parts.username is not None or parts.password is not None:
            raise SSRFError("URL credentials are not allowed")
        host = parts.hostname.rstrip(".")
        if host.lower() == "localhost" or host.lower().endswith(".localhost"):
            raise SSRFError("local targets are not allowed")
        try:
            literal = ipaddress.ip_address(host.split("%", 1)[0])
        except ValueError:
            literal = None
        if literal is not None and not _public_address(str(literal)):
            raise SSRFError("non-public target address")
        return host, port or (443 if parts.scheme == "https" else 80)

    def _resolve_and_validate(self, url: str) -> None:
        # First policy check is intentionally before DNS.
        host, port = self._validate_url(url)
        try:
            records = list(self.resolver(host, port, type=socket.SOCK_STREAM))
        except (OSError, socket.gaierror) as exc:
            raise SSRFError(f"DNS resolution failed for {host}") from exc
        if not records:
            raise SSRFError(f"DNS returned no addresses for {host}")
        addresses: list[str] = []
        for record in records:
            try:
                addresses.append(record[4][0])  # getaddrinfo-compatible result
            except (IndexError, TypeError):
                # A simple iterable of address strings is convenient for
                # deterministic callers and tests.
                if isinstance(record, str):
                    addresses.append(record)
        if not addresses or any(not _public_address(address) for address in addresses):
            raise SSRFError(f"DNS resolved {host} to a non-public address")

    def _candidate(self, url: str, *, discovered_from: Optional[str],
                   source_promotion: Optional[str]) -> Candidate:
        return Candidate(
            url=url,
            canonical_url=canonicalize_url(url),
            original_url=url,
            campaign_parameters=campaign_parameters(url),
            discovered_from=discovered_from,
            source_promotion=source_promotion,
        )

    def expand(self, url: str, *, source_promotion: str = "") -> ExpansionResult:
        result = ExpansionResult(original_url=url)
        current = url
        seen: set[str] = set()
        response: Optional[httpx.Response] = None

        while True:
            loop_key = canonicalize_url(current)
            if loop_key in seen:
                result.termination_reason = "redirect_loop"
                return result
            seen.add(loop_key)
            if result.requests_made >= self.max_requests:
                raise RequestBudgetExceeded("request budget exhausted")

            # Repeated on every iteration: once before DNS and once on every
            # address returned by DNS inside this method.
            self._resolve_and_validate(current)
            result.requests_made += 1
            response = self.client.get(current, follow_redirects=False,
                                       timeout=self.timeout)
            redirect_destination = None
            if response.status_code in REDIRECT_STATUSES:
                location = response.headers.get("location")
                if location:
                    redirect_destination = urljoin(current, location)
            result.hops.append(RedirectHop(
                status_code=response.status_code,
                timestamp=self.clock().astimezone(timezone.utc).isoformat(),
                source_promotion=source_promotion,
                # A terminal response still has a destination: the URL that
                # answered.  This keeps every audit record self-contained.
                destination=redirect_destination or str(response.url),
                source=current,
            ))
            if redirect_destination is None:
                break
            if len(result.hops) > self.max_redirects:
                raise RedirectBudgetExceeded("redirect budget exhausted")
            # Validate redirect syntax/address policy now as well as immediately
            # before its request on the next iteration.
            self._validate_url(redirect_destination)
            current = redirect_destination

        host = (urlsplit(current).hostname or "").lower().rstrip(".")
        if host in self.link_in_bio_hosts:
            parser = _Links()
            parser.feed(response.text)
            deduped: set[str] = set()
            for href in parser.urls:
                outbound = urljoin(current, href)
                parts = urlsplit(outbound)
                if parts.scheme not in ("http", "https") or not parts.hostname:
                    continue
                outbound_host = parts.hostname.lower().rstrip(".")
                if outbound_host == host or outbound_host.endswith("." + host):
                    continue
                key = canonicalize_url(outbound)
                if key in deduped:
                    continue
                deduped.add(key)
                # Outbound links are new candidates.  They retain provenance,
                # but deliberately do not inherit the platform's promotion.
                result.candidates.append(self._candidate(
                    outbound, discovered_from=current, source_promotion=None))
        else:
            result.candidates.append(self._candidate(
                current, discovered_from=url if current != url else None,
                source_promotion=source_promotion or None))
        return result

    def close(self) -> None:
        self.client.close()
