"""Co-signed delivery receipts, agent side (SPEC v0.2.1, section 7).

The agent signs only what it can verify:

- ``result_hash`` = sha256 of the exact response body bytes the agent emits.
- ``task_hash`` is computed by the client with its private salt and sent in
  the ``TrustLayer-Task-Hash`` header; the agent signs it as a commitment of
  the client, without recomputing it.

Delivery object::

    {"v":1, "agent_id", "capability_id", "nonce", "task_hash",
     "result_hash", "timestamp", "kid"} + "signature"

Signature: Ed25519 over the JCS form of the object without ``signature``,
base64url-encoded. The whole delivery travels as base64url(JSON) in the
``TrustLayer-Delivery`` response header. Everything is optional: without a
``TrustLayer-Nonce`` request header the agent responds exactly as before.
"""

from __future__ import annotations

import binascii
import datetime as dt
import hashlib
import re
import secrets
from typing import Any
from urllib.parse import quote

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .canon import canonicalize
from .keys import b64u_decode, b64u_encode

DELIVERY_VERSION = 1
MAX_SKEW = dt.timedelta(hours=24)
NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{16,64}$")  # 16-64 base64url chars
HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class DeliveryError(ValueError):
    """Invalid nonce/task-hash or malformed delivery."""


def new_nonce() -> str:
    """Random nonce: 16 bytes, base64url (22 chars, within 16-64)."""
    return b64u_encode(secrets.token_bytes(16))


def result_hash(body: bytes) -> str:
    return "sha256:" + hashlib.sha256(body).hexdigest()


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def make_delivery(*, priv: Ed25519PrivateKey, kid: str, agent_id: str,
                  capability_id: str, nonce: str, task_hash: str,
                  body: bytes, now: dt.datetime | None = None) -> dict[str, Any]:
    """Build and sign a delivery object for an exact response body."""
    obj: dict[str, Any] = {
        "v": DELIVERY_VERSION,
        "agent_id": agent_id,
        "capability_id": capability_id,
        "nonce": nonce,
        "task_hash": task_hash,
        "result_hash": result_hash(body),
        "timestamp": (now or _now()).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "kid": kid,
    }
    obj["signature"] = b64u_encode(priv.sign(canonicalize(obj)))
    return obj


def encode_delivery(delivery: dict[str, Any]) -> str:
    """Serialize a delivery as the header value: base64url(JSON)."""
    return b64u_encode(canonicalize(delivery))


def decode_delivery(header_value: str) -> dict[str, Any]:
    import json

    try:
        obj = json.loads(b64u_decode(header_value.strip()))
    except (ValueError, binascii.Error) as exc:
        raise DeliveryError(f"malformed delivery header: {exc}") from exc
    if not isinstance(obj, dict):
        raise DeliveryError("delivery must be a JSON object")
    return obj


def validate_request(nonce: str | None, task_hash: str | None) -> None:
    """Server-side validation of the client headers (call before signing).

    Only called when TrustLayer-Nonce is present. Raises DeliveryError with a
    clear message on any violation.
    """
    if not nonce or not NONCE_RE.match(nonce):
        raise DeliveryError(
            "TrustLayer-Nonce must be 16-64 base64url characters")
    if not task_hash or not HASH_RE.match(task_hash.lower()):
        raise DeliveryError(
            "TrustLayer-Task-Hash must be sha256:<64 hex characters>")


def verify_delivery(delivery: dict[str, Any], did_doc: dict[str, Any],
                    body: bytes, *, now: dt.datetime | None = None) -> str | None:
    """Verify a delivery object against the agent's did.json and body bytes.

    Returns None when valid; a reason code otherwise.
    """
    sig = delivery.get("signature")
    if not isinstance(sig, str):
        return "missing_signature"
    kid = delivery.get("kid")
    key = None
    for m in did_doc.get("verificationMethod", []) or []:
        if isinstance(m, dict) and m.get("id") == kid:
            key = m
            break
    if not key:
        return "key_not_found"
    if kid not in (did_doc.get("assertionMethod") or []):
        return "key_not_in_assertion"
    body_obj = {k: v for k, v in delivery.items() if k != "signature"}
    try:
        from .keys import jwk_to_raw
        raw = jwk_to_raw(key["publicKeyJwk"])
        pub = Ed25519PublicKey.from_public_bytes(raw)
        pub.verify(b64u_decode(sig), canonicalize(body_obj))
    except (InvalidSignature, ValueError, KeyError, TypeError):
        return "bad_signature"
    if body_obj.get("result_hash") != result_hash(body):
        return "result_hash_mismatch"
    ts = delivery.get("timestamp")
    if not isinstance(ts, str):
        return "bad_timestamp"
    try:
        t = dt.datetime.fromisoformat(ts.replace("Z", "+00:00"))
        if t.tzinfo is None:
            t = t.replace(tzinfo=dt.timezone.utc)
    except ValueError:
        return "bad_timestamp"
    delta = abs((now or _now()) - t)
    if delta > MAX_SKEW:
        return "timestamp_out_of_range"
    return None  # valid


def delivery_response_headers(delivery: dict[str, Any]) -> dict[str, str]:
    """Headers to attach to the agent's response."""
    return {
        "TrustLayer-Delivery": encode_delivery(delivery),
        "TrustLayer-Delivery-Kid": quote(delivery.get("kid", "")),
    }
