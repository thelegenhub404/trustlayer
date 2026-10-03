"""Safe fetching: the only module allowed to make outbound requests.

Mitigations (plan section 11.1):
- https only;
- resolve DNS up front and reject private, loopback, link-local and cloud
  metadata IPs;
- pin the resolved IP for the connection (prevents DNS rebinding) while using
  the real hostname for SNI and certificate verification;
- at most 3 redirects, same host only;
- 256 KB response limit; 10 s timeout;
- identifiable User-Agent with contact URL.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import socket
import ssl
from typing import Any
from urllib.parse import urlsplit

MAX_BODY = 256 * 1024
MAX_REDIRECTS = 3
TIMEOUT_S = 10.0
USER_AGENT = "TrustLayerCrawler/0.2 (+https://snaypy.com/crawler; crawler@snaypy.com)"

BLOCKED_NETS = [
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
        "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
        "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
        "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "::1/128",
        "fe80::/10", "fc00::/7", "ff00::/8", "2001:db8::/32",
    )
]

# Cloud metadata hostnames (AWS/GCP/Azure).
_CLOUD_HOSTNAMES = {"metadata.google.internal", "metadata.goog"}


class SafeFetchError(Exception):
    """Any safe-fetch failure (network, policy or size)."""


def _check_ip(ip: str) -> None:
    addr = ipaddress.ip_address(ip)
    for net in BLOCKED_NETS:
        if addr in net:
            raise SafeFetchError(f"private/blocked address: {ip}")


def resolve_host(host: str) -> str:
    """Resolve *host* and return the first permitted IP."""
    if host.lower() in _CLOUD_HOSTNAMES:
        raise SafeFetchError("cloud metadata host blocked")
    try:
        infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise SafeFetchError(f"could not resolve {host}: {exc}") from exc
    last_err: SafeFetchError | None = None
    for info in infos:
        ip = info[4][0]
        try:
            _check_ip(ip)
            return ip
        except SafeFetchError as exc:
            last_err = exc
    raise SafeFetchError(f"no valid IP for {host}") from last_err


class _PinnedConnection(http.client.HTTPSConnection):
    """HTTPSConnection that dials a pinned IP but uses the host for SNI."""

    def __init__(self, host: str, ip: str, port: int, timeout: float):
        super().__init__(host, port, timeout=timeout)
        self._pinned_ip = ip

    def connect(self) -> None:  # type: ignore[override]
        # DNS rebinding defense: dial the resolved IP exactly once.
        self.sock = socket.create_connection(
            (self._pinned_ip, self.port), timeout=self.timeout)
        if self._tunnel_host:
            self._tunnel()  # pragma: no cover
        ctx = ssl.create_default_context()
        self.sock = ctx.wrap_socket(self.sock, server_hostname=self.host)


def fetch(url: str, *, method: str = "GET", headers: dict[str, str] | None = None,
          max_redirects: int = MAX_REDIRECTS) -> tuple[int, bytes, dict[str, str]]:
    """Fetch *url* safely. Returns (status, body, headers)."""
    parts = urlsplit(url)
    if parts.scheme != "https":
        raise SafeFetchError("https only")
    host = parts.hostname
    if not host:
        raise SafeFetchError("URL without host")
    port = parts.port or 443

    ip = resolve_host(host)
    try:
        conn = _PinnedConnection(host, ip, port, TIMEOUT_S)
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        send_headers = {
            "Host": host if port == 443 else f"{host}:{port}",
            "User-Agent": USER_AGENT,
            "Accept": "application/json;q=0.9, text/html;q=0.5, */*;q=0.1",
        }
        if headers:
            send_headers.update(headers)
        conn.request(method, path, headers=send_headers)
        resp = conn.getresponse()
        length = resp.getheader("Content-Length")
        if length and int(length) > MAX_BODY:
            raise SafeFetchError("body larger than the 256 KB limit")
        body = resp.read(MAX_BODY + 1)
        if len(body) > MAX_BODY:
            raise SafeFetchError("body larger than the 256 KB limit")
        resp_headers = {k.lower(): v for k, v in resp.getheaders()}
        status = resp.status
        conn.close()
    except SafeFetchError:
        raise
    except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
        raise SafeFetchError(f"network failure: {exc}") from exc

    # Redirects: at most 3, same host only.
    if 300 <= status < 400:
        loc = resp_headers.get("location")
        if loc:
            target = urlsplit(loc if "://" in loc else f"https://{host}{loc}")
            if max_redirects <= 0:
                raise SafeFetchError("too many redirects")
            if not target.hostname or target.hostname.lower() != host.lower():
                raise SafeFetchError("redirect to a different host")
            return fetch(target._replace(scheme="https").geturl(), method=method,
                         headers=headers, max_redirects=max_redirects - 1)
    return status, body, resp_headers


def fetch_json(url: str) -> tuple[int, Any, dict[str, str]]:
    """Fetch and parse JSON. Returns (status, value, headers)."""
    status, body, headers = fetch(url)
    try:
        return status, json.loads(body.decode("utf-8")), headers
    except (UnicodeDecodeError, ValueError) as exc:
        raise SafeFetchError(f"response is not valid JSON: {exc}") from exc
