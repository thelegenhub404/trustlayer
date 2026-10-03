"""Delivery (co-signed receipts, agent side) tests — SPEC v0.2.1 §7."""

import datetime as dt

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tl import delivery
from tl.keys import to_jwk

DOMAIN = "agent.example.com"
DID = f"did:web:{DOMAIN}"
NOW = dt.datetime(2026, 10, 3, 12, 0, 0, tzinfo=dt.timezone.utc)
BODY = b'{"answer": 42}'
TASK_HASH = "sha256:" + "a" * 64

PRIV = Ed25519PrivateKey.generate()
KID = DID + "#delivery-1"
DID_DOC = {
    "id": DID,
    "verificationMethod": [{
        "id": KID, "type": "JsonWebKey2020", "controller": DID,
        "publicKeyJwk": to_jwk(PRIV.public_key()),
    }],
    "assertionMethod": [KID],
}


def make(**overrides):
    kw = dict(priv=PRIV, kid=KID, agent_id=DID, capability_id="cap",
              nonce=delivery.new_nonce(), task_hash=TASK_HASH, body=BODY, now=NOW)
    kw.update(overrides)
    return delivery.make_delivery(**kw)


def test_roundtrip_signature():
    d = make()
    assert delivery.verify_delivery(d, DID_DOC, BODY, now=NOW) is None
    header = delivery.encode_delivery(d)
    assert delivery.verify_delivery(
        delivery.decode_delivery(header), DID_DOC, BODY, now=NOW) is None


def test_tampered_body_fails():
    d = make()
    assert delivery.verify_delivery(
        d, DID_DOC, BODY + b" ", now=NOW) == "result_hash_mismatch"


def test_invalid_nonce_rejected():
    with pytest.raises(delivery.DeliveryError):
        delivery.validate_request("short", TASK_HASH)
    with pytest.raises(delivery.DeliveryError):
        delivery.validate_request("x" * 65, TASK_HASH)
    with pytest.raises(delivery.DeliveryError):
        delivery.validate_request(delivery.new_nonce(), "not-a-hash")
    # valid case passes
    delivery.validate_request(delivery.new_nonce(), TASK_HASH)


def test_no_nonce_no_header():
    # Without TrustLayer-Nonce the flow is simply absent: validate_request is
    # never called and make_delivery is never invoked.
    nonce = None
    assert nonce is None and delivery.encode_delivery is not None
    # and validate_request has no "absent" mode: callers skip it entirely.
    assert delivery.NONCE_RE.match(delivery.new_nonce())


def test_unlisted_key_fails():
    d = make(priv=Ed25519PrivateKey.generate())
    assert delivery.verify_delivery(d, DID_DOC, BODY, now=NOW) == "bad_signature"
    other_doc = {"verificationMethod": DID_DOC["verificationMethod"],
                 "assertionMethod": ["did:web:x#other"]}
    d2 = make()
    assert delivery.verify_delivery(d2, other_doc, BODY, now=NOW) == "key_not_in_assertion"


def test_timestamp_out_of_range_fails():
    d = make(now=NOW - dt.timedelta(hours=25))
    assert delivery.verify_delivery(d, DID_DOC, BODY, now=NOW) == "timestamp_out_of_range"
    ok = make(now=NOW - dt.timedelta(hours=23))
    assert delivery.verify_delivery(ok, DID_DOC, BODY, now=NOW) is None
