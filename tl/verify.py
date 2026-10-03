"""Identity verification algorithm (plan section 6).

Input: domain. Output: level (L0-L2), list of reasons and result fingerprint.
Every check is recorded individually so the /v1/verify endpoint can show the
full breakdown.
"""

from __future__ import annotations

import datetime as dt
import re
from typing import Any
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canon import canonicalize
from .keys import b64u_decode, fingerprint_from_raw, jwk_to_raw
from . import netsafe

# Minimal two-part public suffix list; the authoritative source lives in
# spec/SPEC.md. Extend via PR when new TLDs appear in seeds.
TWO_PART_SUFFIXES = {"co.uk", "com.ar", "com.br", "com.mx", "com.au", "co.jp",
                     "com.tr", "co.za", "com.cn", "co.in", "org.uk"}


class _Result:
    def __init__(self) -> None:
        self.checks: list[dict[str, Any]] = []
        self.level = "L0"

    def check(self, name: str, ok: bool, reason: str | None = None) -> bool:
        entry: dict[str, Any] = {"name": name, "ok": ok}
        if reason and not ok:
            entry["reason"] = reason
        self.checks.append(entry)
        return ok

    def fail(self, name: str, reason: str) -> bool:
        return self.check(name, False, reason)


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _parse_ts(value: Any) -> dt.datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=dt.timezone.utc)
        return parsed
    except ValueError:
        return None


def txt_fingerprints(domain: str) -> list[str]:
    """Read TXT _trustlayer.DOMAIN and return the published fingerprints."""
    import dns.resolver

    fps: list[str] = []
    try:
        answers = dns.resolver.resolve(f"_trustlayer.{domain}", "TXT")
        for rdata in answers:
            for text in getattr(rdata, "strings", []):
                s = text.decode("ascii", "ignore")
                m = re.search(r"fp=sha256:([0-9a-fA-F]{64})", s)
                if m:
                    fps.append("sha256:" + m.group(1).lower())
    except Exception:
        return fps
    return fps


def same_etld_plus_one(host_a: str, host_b: str) -> bool:
    """Conservative eTLD+1 comparison using a minimal public suffix list."""

    def registrable(h: str) -> str:
        labels = h.lower().rstrip(".").split(".")
        if len(labels) >= 3 and ".".join(labels[-2:]) in TWO_PART_SUFFIXES:
            return ".".join(labels[-3:])
        return ".".join(labels[-2:]) if len(labels) >= 2 else h

    return registrable(host_a) == registrable(host_b)


def verify_signature(card: dict[str, Any], did_doc: dict[str, Any]) -> str | None:
    """Verify the trustlayer.json signature against the did.json document.

    Returns None when valid; a reason code otherwise.
    """
    sig = card.get("signature") or {}
    if not isinstance(sig, dict) or sig.get("alg") != "Ed25519":
        return "bad_alg"
    kid = sig.get("kid")
    key = None
    for m in did_doc.get("verificationMethod", []) or []:
        if isinstance(m, dict) and m.get("id") == kid:
            key = m
            break
    if not key:
        return "key_not_found"
    assertion = did_doc.get("assertionMethod") or []
    if kid not in assertion:
        return "key_not_in_assertion"
    try:
        raw = jwk_to_raw(key.get("publicKeyJwk") or {})
    except ValueError:
        return "bad_key"
    try:
        sig_bytes = b64u_decode(sig.get("value", ""))
    except ValueError:
        return "bad_signature_encoding"
    body = {k: v for k, v in card.items() if k != "signature"}
    try:
        pub = Ed25519PublicKey.from_public_bytes(raw)
        pub.verify(sig_bytes, canonicalize(body))
    except (InvalidSignature, ValueError, KeyError, TypeError):
        return "bad_signature"
    return None  # valid signature


def verify_domain(domain: str, *, now: dt.datetime | None = None,
                  fetch_dns: bool = True,
                  fetcher: Any = None) -> dict[str, Any]:
    """Run the full section-6 algorithm on *domain*.

    fetcher lets tests inject canned responses; defaults to netsafe.
    Returns {domain, level, checks, red_flags}.
    """
    fetcher = fetcher or netsafe
    res = _Result()
    now = now or _now()
    domain = domain.strip().lower().rstrip(".")
    red_flags: list[str] = []
    expected_did = f"did:web:{domain}"

    # 1. Safe download of did.json
    try:
        status, did_doc, _ = fetcher.fetch_json(f"https://{domain}/.well-known/did.json")
        if status != 200 or not isinstance(did_doc, dict):
            raise netsafe.SafeFetchError(f"status {status}")
        res.check("did_json", True)
    except netsafe.SafeFetchError as exc:
        res.fail("did_json", f"could not download did.json: {exc}")
        return _finalize(res, red_flags, domain)

    # 2. Identity: id == did:web:host and agent_id matches
    if not res.check("did_matches_host", did_doc.get("id") == expected_did,
                     f"id={did_doc.get('id')!r} expected {expected_did!r}"):
        return _finalize(res, red_flags, domain)

    try:
        status, card, _ = fetcher.fetch_json(
            f"https://{domain}/.well-known/trustlayer.json")
        if status != 200 or not isinstance(card, dict):
            raise netsafe.SafeFetchError(f"status {status}")
        res.check("trustlayer_json", True)
    except netsafe.SafeFetchError as exc:
        res.fail("trustlayer_json", f"could not download trustlayer.json: {exc}")
        return _finalize(res, red_flags, domain)

    if not res.check("agent_id_matches", card.get("agent_id") == expected_did,
                     f"agent_id={card.get('agent_id')!r}"):
        return _finalize(res, red_flags, domain)

    # 3. Key located by signature.kid: Ed25519 and listed in assertionMethod
    reason = verify_signature(card, did_doc)
    if reason in ("key_not_found", "key_not_in_assertion", "bad_alg", "bad_key"):
        res.fail("signature", reason or "signature error")
        return _finalize(res, red_flags, domain)
    sig_ok = res.check("signature", reason is None, reason)
    if not sig_ok:
        res.level = "L1"  # broken signature: at most L1, keep giving breakdown

    # 4. Temporal validity
    issued = _parse_ts(card.get("issued_at"))
    expires = _parse_ts(card.get("expires_at"))
    if res.check("key_not_expired",
                 bool(issued and expires and issued <= now < expires),
                 "outside issued_at/expires_at"):
        if expires and (expires - now) > dt.timedelta(days=90):
            red_flags.append("expires_at more than 90 days in the future")
    else:
        res.level = "L1"

    # 5. DNS anchoring
    kid = (card.get("signature") or {}).get("kid")
    key_entry = next((m for m in did_doc.get("verificationMethod", [])
                      if isinstance(m, dict) and m.get("id") == kid), None)
    revoked = card.get("revoked_kids") or []
    fp = None
    if key_entry and kid not in revoked:
        try:
            fp = fingerprint_from_raw(jwk_to_raw(key_entry.get("publicKeyJwk") or {}))
            res.check("key_fingerprint", True)
        except ValueError:
            res.fail("key_fingerprint", "unreadable key")
            res.level = "L1"
    else:
        res.fail("key_fingerprint", "key revoked or missing")
        res.level = "L1"

    if fp is not None:
        if not fetch_dns:
            res.check("dns_anchor", True, "skipped (fetch_dns=False)")
        else:
            dns_fps = txt_fingerprints(domain)
            res.check("dns_anchor", fp in dns_fps,
                      f"fingerprint {fp} not present in TXT _trustlayer.{domain}")
            if fp not in dns_fps:
                res.level = "L1"

    # 6. Endpoints within the same eTLD+1
    declared_services = {s.get("id") for s in (did_doc.get("service") or [])
                         if isinstance(s, dict)}
    for cap in card.get("capabilities", []) or []:
        ep = cap.get("endpoint") or ""
        host = urlsplit(ep).hostname or ""
        if not host:
            red_flags.append(f"capability {cap.get('id')!r} has no valid endpoint")
        elif not same_etld_plus_one(host, domain) and cap.get("id") not in declared_services:
            red_flags.append(
                f"third-party endpoint in capability {cap.get('id')!r}: {ep}")

    return _finalize(res, red_flags, domain)


def _finalize(res: _Result, red_flags: list[str], domain: str) -> dict[str, Any]:
    # L0 when identity basics failed (hard reject, section 6 step 2) or the
    # artifacts could not be fetched; L1 when the structure is valid but some
    # check failed; L2 when everything passed.
    basic_ok = all(c["ok"] for c in res.checks
                   if c["name"] in ("did_json", "did_matches_host",
                                    "agent_id_matches"))
    any_fail = not all(c["ok"] for c in res.checks)
    if not basic_ok:
        level = "L0"
    elif any_fail:
        level = "L1"
    else:
        level = "L2"
    return {
        "domain": domain,
        "level": level,
        "checks": res.checks,
        "red_flags": red_flags,
    }
