"""Two-stage validation of untrusted discovery results.

Stage one never contacts a candidate.  It ranks inexpensive search/CT metadata
so that the considerably more expensive (and dangerous) network work is only
performed for the best candidates.  Stage two treats every URL as hostile and
returns an explicit validation state; a fetch failure is not a clean page.
"""

from __future__ import annotations

import hashlib
import http.client
import ipaddress
import re
import socket
import ssl
from html.parser import HTMLParser
from typing import Any, Callable, Iterable
from urllib.parse import urljoin, urlsplit


DEFAULT_CONTENT_TYPES = frozenset({"text/html", "application/xhtml+xml"})
REDIRECTS = frozenset({301, 302, 303, 307, 308})
METADATA_HOSTS = frozenset({
    "metadata.google.internal", "metadata.google", "instance-data",
})
SUSPICIOUS = re.compile(
    r"\b(login|verify|verification|password|pin|otp|wallet|payment|paybill|"
    r"account|activate|activation|fee|urgent|bonus|loan|support|secure)\b", re.I
)
PROMOTION = re.compile(r"\b(sponsored|promoted|advertisement|paid)\b", re.I)


class FetchBlocked(ValueError):
    """The target violates the outbound network policy."""


class BodyTooLarge(ValueError):
    """The response exceeded the configured byte budget."""


def _host_is_metadata(host: str) -> bool:
    host = host.rstrip(".").lower()
    return host in METADATA_HOSTS or host.endswith(".metadata.google.internal")


def _public_ip(value: str) -> bool:
    ip = ipaddress.ip_address(value.split("%", 1)[0])
    # is_global rejects private, loopback, link-local, reserved, unspecified,
    # multicast, and documentation ranges on supported Python versions.
    return ip.is_global


def rank_candidates(candidates: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Cheaply rank candidates without making network requests.

    The score is deliberately a triage score, not a risk verdict.  ``scored_on``
    identifies exactly which supplied metadata fields contributed evidence.
    """
    ranked = []
    for candidate in candidates:
        item = dict(candidate)
        fields = {
            "url": str(item.get("url") or ""),
            "title": str(item.get("title") or ""),
            "snippet": str(item.get("snippet") or item.get("summary") or ""),
            "source": str(item.get("source") or ""),
            "promotion_context": str(item.get("promotion_context") or item.get("query") or ""),
        }
        score, scored_on = 0, []
        weights = {"url": 5, "title": 4, "snippet": 3, "source": 1,
                   "promotion_context": 3}
        for name, value in fields.items():
            if not value:
                continue
            hits = len(SUSPICIOUS.findall(value))
            promotion_hit = name == "promotion_context" and PROMOTION.search(value)
            if hits or promotion_hit:
                scored_on.append(name)
                score += min(25, hits * weights[name]) + (5 if promotion_hit else 0)
        try:
            host = urlsplit(fields["url"]).hostname or ""
            if host and (host.count("-") >= 2 or host.startswith("xn--")):
                score += 8
                if "url" not in scored_on:
                    scored_on.append("url")
        except ValueError:
            score += 10
            if "url" not in scored_on:
                scored_on.append("url")
        item["stage_one_score"] = min(100, score)
        item["validation_status"] = "not_validated"
        item["scored_on"] = sorted(scored_on)
        ranked.append(item)
    return sorted(ranked, key=lambda x: x["stage_one_score"], reverse=True)


class _Extractor(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.hidden = 0
        self.text: list[str] = []
        self.forms: list[dict[str, Any]] = []
        self.credential_fields: list[dict[str, str]] = []
        self.payment_identifiers: set[str] = set()
        self.outbound_links: set[str] = set()
        self.favicons: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr = {k.lower(): (v or "") for k, v in attrs}
        if tag in {"script", "style", "noscript", "template", "svg"} or "hidden" in attr:
            self.hidden += 1
        if tag == "form":
            self.forms.append({"action": urljoin(self.base_url, attr.get("action", "")),
                               "method": attr.get("method", "get").upper()})
        if tag in {"input", "textarea"}:
            kind = attr.get("type", "text").lower()
            identity = " ".join((attr.get("name", ""), attr.get("id", ""),
                                  attr.get("autocomplete", "")))
            if kind == "password" or re.search(r"\b(user|email|login|pass|pin|otp|card|cvv)\b", identity, re.I):
                self.credential_fields.append({"type": kind, "name": attr.get("name", "")})
        if tag in {"a", "link"}:
            href = attr.get("href")
            if href:
                absolute = urljoin(self.base_url, href)
                if tag == "link" and "icon" in attr.get("rel", "").lower():
                    self.favicons.append(absolute)
                elif tag == "a" and urlsplit(absolute).scheme in {"http", "https"}:
                    self.outbound_links.add(absolute)

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style", "noscript", "template", "svg"} and self.hidden:
            self.hidden -= 1

    def handle_data(self, data: str) -> None:
        if not self.hidden and data.strip():
            self.text.append(data.strip())


class HardenedFetcher:
    """A small, bounded HTTP client for attacker-controlled candidate URLs."""

    def __init__(self, *, timeout: float = 10, max_redirects: int = 4,
                 max_body_bytes: int = 2_000_000,
                 allowed_content_types: Iterable[str] = DEFAULT_CONTENT_TYPES,
                 resolver: Callable[..., Any] = socket.getaddrinfo) -> None:
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.max_body_bytes = max_body_bytes
        self.allowed_content_types = frozenset(x.lower() for x in allowed_content_types)
        self.resolver = resolver

    def _resolve(self, host: str, port: int) -> list[str]:
        if _host_is_metadata(host):
            raise FetchBlocked("metadata-service hostname")
        try:
            literal = ipaddress.ip_address(host.split("%", 1)[0])
            addresses = [str(literal)]
        except ValueError:
            addresses = list(dict.fromkeys(
                row[4][0] for row in self.resolver(host, port, type=socket.SOCK_STREAM)
            ))
        if not addresses:
            raise socket.gaierror("hostname returned no addresses")
        if any(not _public_ip(address) for address in addresses):
            raise FetchBlocked("hostname resolves to a non-public address")
        return addresses

    def _request(self, url: str) -> tuple[http.client.HTTPResponse, http.client.HTTPConnection]:
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"}:
            raise FetchBlocked("only HTTP and HTTPS URLs are allowed")
        if not parsed.hostname or parsed.username or parsed.password:
            raise FetchBlocked("URL must contain a hostname and no credentials")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        # Resolve once for policy and connect to that exact address, preventing
        # a second DNS lookup from turning validation into a rebinding race.
        address = self._resolve(parsed.hostname, port)[0]
        if parsed.scheme == "https":
            context = ssl.create_default_context()
            conn = http.client.HTTPSConnection(address, port, timeout=self.timeout,
                                                context=context)
            # HTTPSConnection would use the IP for SNI/certificate validation.
            # Override its tunnel host only through a pinned socket connection.
            raw = socket.create_connection((address, port), self.timeout)
            conn.sock = context.wrap_socket(raw, server_hostname=parsed.hostname)
        else:
            conn = http.client.HTTPConnection(address, port, timeout=self.timeout)
        target = parsed.path or "/"
        if parsed.query:
            target += "?" + parsed.query
        host_header = parsed.hostname
        if parsed.port and parsed.port not in {80, 443}:
            host_header += f":{parsed.port}"
        conn.request("GET", target, headers={"Host": host_header,
                    "User-Agent": "Watchtower-Validator/1.0", "Accept": "text/html,application/xhtml+xml",
                    "Connection": "close"})
        return conn.getresponse(), conn

    def fetch(self, url: str) -> dict[str, Any]:
        current, redirects = url, []
        try:
            for hop in range(self.max_redirects + 1):
                response, conn = self._request(current)
                try:
                    if response.status in REDIRECTS:
                        location = response.getheader("Location")
                        if not location:
                            return self._failure("http_error", current, response.status, redirects)
                        if hop == self.max_redirects:
                            return self._failure("blocked", current, response.status, redirects,
                                                 "redirect limit exceeded")
                        current = urljoin(current, location)
                        # The next iteration re-parses and re-resolves every redirect.
                        redirects.append(current)
                        continue
                    if not 200 <= response.status < 300:
                        return self._failure("http_error", current, response.status, redirects)
                    content_type = response.getheader("Content-Type", "").split(";", 1)[0].lower()
                    if content_type not in self.allowed_content_types:
                        return self._failure("content_type_blocked", current, response.status,
                                             redirects, content_type or "missing content type")
                    body = self._read_bounded(response)
                finally:
                    conn.close()
                return self._analyze(current, response.status, redirects, body)
        except FetchBlocked as exc:
            return self._failure("blocked", current, None, redirects, str(exc))
        except socket.gaierror as exc:
            return self._failure("dns_error", current, None, redirects, str(exc))
        except (socket.timeout, TimeoutError) as exc:
            return self._failure("timeout", current, None, redirects, str(exc))
        except (ssl.SSLError, ssl.CertificateError) as exc:
            return self._failure("tls_error", current, None, redirects, str(exc))
        except BodyTooLarge as exc:
            return self._failure("body_too_large", current, None, redirects, str(exc))
        except (http.client.HTTPException, OSError) as exc:
            return self._failure("http_error", current, None, redirects, str(exc))

    def _read_bounded(self, response: http.client.HTTPResponse) -> bytes:
        length = response.getheader("Content-Length")
        if length and int(length) > self.max_body_bytes:
            raise BodyTooLarge("declared body exceeds limit")
        body = response.read(self.max_body_bytes + 1)
        if len(body) > self.max_body_bytes:
            raise BodyTooLarge("response body exceeds limit")
        return body

    @staticmethod
    def _failure(status: str, url: str, http_status: int | None,
                 redirects: list[str], error: str = "") -> dict[str, Any]:
        return {"validation_status": status, "scored_on": [], "url": url,
                "http_status": http_status, "redirects": redirects, "error": error}

    def _analyze(self, url: str, status: int, redirects: list[str], body: bytes) -> dict[str, Any]:
        text = body.decode("utf-8", errors="replace")
        parser = _Extractor(url)
        parser.feed(text)
        visible = " ".join(parser.text)
        payment_patterns = re.findall(
            r"(?i)\b(?:paybill|till|merchant|wallet|iban|account)\s*(?:number|no\.?|id)?\s*[:#-]?\s*([A-Z0-9-]{4,34})",
            visible,
        )
        parser.payment_identifiers.update(payment_patterns)
        normalized = re.sub(r"\s+", " ", visible).strip()
        return {
            "validation_status": "validated", "scored_on": ["page_content"],
            "url": url, "http_status": status, "redirects": redirects,
            "visible_text": normalized, "forms": parser.forms,
            "credential_fields": parser.credential_fields,
            "payment_identifiers": sorted(parser.payment_identifiers),
            "outbound_links": sorted(parser.outbound_links),
            # Hash favicon references without making extra, unvalidated requests.
            "favicon_hashes": [hashlib.sha256(x.encode()).hexdigest() for x in parser.favicons],
            "page_fingerprint": hashlib.sha256(normalized.lower().encode()).hexdigest(),
        }


def validate_candidates(candidates: Iterable[dict[str, Any]], *, limit: int = 10,
                        fetcher: HardenedFetcher | None = None) -> list[dict[str, Any]]:
    """Rank every candidate, then fetch only the highest-ranked ``limit``."""
    if limit < 0:
        raise ValueError("limit must be non-negative")
    ranked = rank_candidates(candidates)
    client = fetcher or HardenedFetcher()
    for item in ranked[:limit]:
        stage_one_sources = set(item.get("scored_on", []))
        validation = client.fetch(str(item.get("url") or ""))
        item.update(validation)
        # Preserve stage-one provenance and add page evidence only on success.
        item["scored_on"] = sorted(stage_one_sources |
                                   set(validation.get("scored_on", [])))
    return ranked
