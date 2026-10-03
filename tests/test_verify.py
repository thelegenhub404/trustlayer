"""Verification algorithm tests with an in-memory fake fetcher (no network)."""

import pytest

import datetime as dt
import json


from tl.canon import canonicalize
from tl.keys import fingerprint, generate_keypair, sign, to_jwk

DOMAIN = "agent.example.com"
DID = f"did:web:{DOMAIN}"
NOW = dt.datetime(2026, 10, 3, 12, 0, 0, tzinfo=dt.timezone.utc)


def make_artifacts(domain=DOMAIN, *, sign_key=None, did_id=None, agent_id=None,
                   mutate_card=None):
    priv, pub = (sign_key, None) if sign_key else generate_keypair()
    did_id = did_id or f"did:web:{domain}"
    kid = did_id + "#key-1"
    did_doc = {
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did_id,
        "verificationMethod": [{
            "id": kid, "type": "JsonWebKey2020", "controller": did_id,
            "publicKeyJwk": to_jwk(pub),
        }],
        "assertionMethod": [kid],
    }
    card = {
        "spec_version": "trustlayer/0.2",
        "agent_id": agent_id or did_id,
        "name": "TestAgent",
        "capabilities": [{
            "id": "test-cap",
            "endpoint": f"https://{domain}/v1/cap",
            "protocol": "https+json",
            "payment": {"method": "none"},
        }],
        "issued_at": "2026-09-01T00:00:00Z",
        "expires_at": "2026-11-01T00:00:00Z",
    }
    if mutate_card:
        mutate_card(card)
    if "signature" not in card:
        card["signature"] = {"alg": "Ed25519", "kid": kid,
                             "value": sign(priv, canonicalize(card))}
    return did_doc, card


class FakeFetcher:
    def __init__(self, did_doc, card, did_host=None, card_host=None):
        self.responses = {
            f"https://{did_host or DOMAIN}/.well-known/did.json": (200, did_doc),
            f"https://{card_host or DOMAIN}/.well-known/trustlayer.json": (200, card),
        }

    def fetch_json(self, url):
        status, doc = self.responses[url]
        return status, doc, {}


def run(did_doc, card, dns_fps, *, domain=DOMAIN, now=NOW):
    import tl.verify as v
    fetcher = FakeFetcher(did_doc, card)
    saved = v.txt_fingerprints
    v.txt_fingerprints = lambda d: dns_fps
    try:
        return v.verify_domain(domain, now=now, fetch_dns=True, fetcher=fetcher)
    finally:
        v.txt_fingerprints = saved


def check_names(result):
    return {c["name"]: c for c in result["checks"]}


def test_valid_agent_reaches_l2():
    did_doc, card = make_artifacts()
    fp = fingerprint(_pub_of(card, did_doc))
    result = run(did_doc, card, [fp])
    assert result["level"] == "L2"
    assert check_names(result)["dns_anchor"]["ok"]
    assert not result["red_flags"]


def _pub_of(card, did_doc):
    from tl.keys import jwk_to_raw
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    kid = card["signature"]["kid"]
    m = next(m for m in did_doc["verificationMethod"] if m["id"] == kid)
    return Ed25519PublicKey.from_public_bytes(jwk_to_raw(m["publicKeyJwk"]))


def test_missing_dns_anchor_caps_at_l1():
    did_doc, card = make_artifacts()
    result = run(did_doc, card, [])  # nothing published
    assert result["level"] == "L1"
    assert not check_names(result)["dns_anchor"]["ok"]


def test_tampered_card_fails_signature():
    did_doc, card = make_artifacts()
    fp = fingerprint(_pub_of(card, did_doc))
    card["name"] = "EvilAgent"  # altered after signing
    result = run(did_doc, card, [fp])
    assert result["level"] == "L1"
    assert check_names(result)["signature"]["reason"] == "bad_signature"


def test_did_id_mismatch_is_rejected():
    did_doc, card = make_artifacts(did_id="did:web:other.example.com")
    result = run(did_doc, card, [])
    assert result["level"] == "L0"
    assert not check_names(result)["did_matches_host"]["ok"]


def test_agent_id_mismatch_rejected():
    did_doc, card = make_artifacts(agent_id="did:web:other.example.com")
    result = run(did_doc, card, [])
    assert result["level"] == "L0"


def test_expired_card_caps_at_l1():
    did_doc, card = make_artifacts()
    fp = fingerprint(_pub_of(card, did_doc))
    late = dt.datetime(2026, 12, 1, tzinfo=dt.timezone.utc)
    result = run(did_doc, card, [fp], now=late)
    assert result["level"] == "L1"
    assert not check_names(result)["key_not_expired"]["ok"]


def test_expiry_far_in_future_is_red_flag():
    did_doc, card = make_artifacts()
    fp = fingerprint(_pub_of(card, did_doc))
    card["expires_at"] = "2027-10-01T00:00:00Z"
    result = run(did_doc, card, [fp])
    assert any("90 days" in f for f in result["red_flags"])


def test_third_party_endpoint_is_red_flag():
    def mutate(card):
        card["capabilities"].append({
            "id": "evil", "endpoint": "https://evil.net/hook",
            "protocol": "https+json", "payment": {"method": "none"}})
    did_doc, card = make_artifacts(mutate_card=mutate)
    fp = fingerprint(_pub_of(card, did_doc))
    result = run(did_doc, card, [fp])
    assert any("evil.net" in f for f in result["red_flags"])
    # declared service silences the flag
    did_doc["service"] = [{"id": "evil"}]
    result = run(did_doc, card, [fp])
    assert not any("evil.net" in f for f in result["red_flags"])


def test_revoked_key_rejected():
    did_doc, card = make_artifacts()
    card["revoked_kids"] = [card["signature"]["kid"]]
    result = run(did_doc, card, [])
    assert result["level"] == "L1"
    assert not check_names(result)["key_fingerprint"]["ok"]


def test_cannot_download_did_is_l0():
    import tl.verify as v
    class Dead:
        def fetch_json(self, url):
            raise v.netsafe.SafeFetchError("boom")
    result = v.verify_domain(DOMAIN, now=NOW, fetch_dns=False, fetcher=Dead())
    assert result["level"] == "L0"


def test_alternative_whitespace_json_signs_differently_but_verify_holds():
    # Signing is over canonical bytes, so two different spacings of the same
    # logical card produce the same canonicalization -> same verification.
    did_doc, card = make_artifacts()
    fp = fingerprint(_pub_of(card, did_doc))
    res1 = run(did_doc, card, [fp])
    res2 = run(json.loads(json.dumps(did_doc)), json.loads(json.dumps(card)), [fp])
    assert res1["level"] == res2["level"] == "L2"


def test_card_signed_by_delivery_key_rejected():
    # v0.2.2: the delivery key lives only in authentication; a card signed
    # with it must not verify.
    def mutate(card):
        card["signature"] = {"alg": "Ed25519",
                             "kid": DID + "#delivery-1", "value": "AA"}
    did_doc, card = make_artifacts(mutate_card=mutate)
    delivery_key = {"id": DID + "#delivery-1", "type": "JsonWebKey2020",
                    "controller": DID, "publicKeyJwk": to_jwk(generate_keypair()[1])}
    did_doc["verificationMethod"].append(delivery_key)
    did_doc["authentication"] = [DID + "#delivery-1"]
    result = run(did_doc, card, [])
    assert result["level"] != "L2"
    assert check_names(result)["signature"]["reason"] == "key_not_in_assertion"


@pytest.mark.skipif(not __import__("os").environ.get("TL_INTEGRATION"),
                    reason="live-network test; set TL_INTEGRATION=1")
def test_snaypy_still_l2_live():
    # (c) v0.2.2: role separation must not affect snaypy.com's identity.
    import tl.verify as v
    result = v.verify_domain("snaypy.com")
    assert result["level"] == "L2"
