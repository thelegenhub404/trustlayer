"""netsafe policy tests: these run without network, only checking rules."""

import pytest

from tl.netsafe import SafeFetchError, _check_ip, resolve_host


def test_private_ips_rejected():
    for ip in ("127.0.0.1", "10.0.0.5", "192.168.1.1", "172.16.0.9",
               "169.254.169.254", "100.64.0.1", "0.0.0.0", "::1",
               "fe80::1", "fd00::1", "224.0.0.1"):
        with pytest.raises(SafeFetchError):
            _check_ip(ip)


def test_public_ip_accepted():
    _check_ip("93.184.216.34")
    _check_ip("2606:2800:220:1:248:1893:25c8:1946")


def test_cloud_metadata_hostname_rejected():
    with pytest.raises(SafeFetchError):
        resolve_host("metadata.google.internal")


def test_http_scheme_rejected():
    with pytest.raises(SafeFetchError):
        from tl.netsafe import fetch
        fetch("http://example.com/x")


def test_unresolvable_host():
    with pytest.raises(SafeFetchError):
        resolve_host("nonexistent-domain-xyz.invalid")
