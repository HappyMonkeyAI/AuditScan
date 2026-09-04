"""Safe, text-only external link intake policy."""
from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from typing import Iterable
from urllib.parse import urlparse
from urllib.request import Request, urlopen

_MAX_BYTES = 1_000_000
_MAX_REDIRECTS = 3
_TIMEOUT = 10
_ALLOWED_MIME = {"text/plain", "text/markdown", "text/html", "application/json"}


@dataclass
class ExternalFetchResult:
    url: str
    status: str
    content: str = ""
    mime_type: str | None = None
    reason: str | None = None
    redirects: int = 0


def _public_host(host: str) -> bool:
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(host, None)}
    except socket.gaierror:
        return False
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if not ip.is_global:
            return False
    return bool(addresses)


def validate_external_url(url: str) -> str | None:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return "only HTTPS URLs are permitted"
    if parsed.username or parsed.password:
        return "URL credentials are prohibited"
    if not parsed.hostname:
        return "URL hostname is missing"
    if not _public_host(parsed.hostname):
        return "hostname does not resolve exclusively to public addresses"
    return None


def fetch_external_text(url: str) -> ExternalFetchResult:
    current = url
    for redirects in range(_MAX_REDIRECTS + 1):
        reason = validate_external_url(current)
        if reason:
            return ExternalFetchResult(current, "blocked", reason=reason, redirects=redirects)
        try:
            request = Request(current, headers={"Accept": "text/plain, text/markdown, text/html, application/json"})
            with urlopen(request, timeout=_TIMEOUT) as response:  # no browser/runtime execution
                mime = response.headers.get_content_type().lower()
                if mime not in _ALLOWED_MIME:
                    return ExternalFetchResult(current, "needs_human_review", mime_type=mime, reason="unsupported MIME type", redirects=redirects)
                length = response.headers.get("Content-Length")
                if length and int(length) > _MAX_BYTES:
                    return ExternalFetchResult(current, "needs_human_review", mime_type=mime, reason="response exceeds size limit", redirects=redirects)
                body = response.read(_MAX_BYTES + 1)
                if len(body) > _MAX_BYTES:
                    return ExternalFetchResult(current, "needs_human_review", mime_type=mime, reason="response exceeds size limit", redirects=redirects)
                return ExternalFetchResult(current, "completed", body.decode("utf-8", errors="replace"), mime, redirects=redirects)
        except Exception as exc:  # network failures are explicit, never clean
            return ExternalFetchResult(current, "failed", reason=type(exc).__name__, redirects=redirects)
    return ExternalFetchResult(current, "blocked", reason="redirect limit exceeded", redirects=_MAX_REDIRECTS)
