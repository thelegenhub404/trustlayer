"""Golden vector generator/validator (spec/test-vectors).

Run as a module:
    python -m tests.vectors          # validate all vectors
    python -m tests.vectors --regen  # regenerate valid vector fixtures
"""

from __future__ import annotations

import datetime as dt
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tl.canon import canonicalize
from tl.keys import sign, to_jwk
from tl.verify import verify_signature

VECTOR_DIR = Path(__file__).resolve().parents[1] / "spec" / "test-vectors"
DOMAIN = "vectors.example.com"
DID = f"did:web:{DOMAIN}"
NOW = dt.datetime.now(dt.timezone.utc)

# Deterministic key for regenerating the canonical vector (seed is public,
# test-only, never used in production).
TEST_SEED = b"\x01" * 32
TEST_PRIV = Ed25519PrivateKey.from_private_bytes(TEST_SEED)
TEST_PUB = TEST_PRIV.public_key()
TEST_KID = DID + "#key-1"


def canonical_vector() -> dict:
    """Byte-exact canonicalization fixture (RFC 8785 style, fixed keys)."""
    body = {"b": 1, "a": [True, None, "x\u00e9"], "c": {"z": 0, "y": -2}}
    return {"name": "canon-basic", "input": body,
            "canonical": canonicalize(body).decode("utf-8")}


def valid_did_doc() -> dict:
    return {
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": DID,
        "verificationMethod": [{
            "id": TEST_KID, "type": "JsonWebKey2020", "controller": DID,
            "publicKeyJwk": to_jwk(TEST_PUB),
        }],
        "assertionMethod": [TEST_KID],
    }


def valid_card() -> dict:
    card = {
        "spec_version": "trustlayer/0.2",
        "agent_id": DID,
        "name": "VectorAgent",
        "capabilities": [{"id": "echo", "endpoint": f"https://{DOMAIN}/v1/echo",
                          "protocol": "https+json", "payment": {"method": "none"}}],
        "issued_at": "2026-01-01T00:00:00Z",
        "expires_at": "2027-01-01T00:00:00Z",
    }
    card["signature"] = {"alg": "Ed25519", "kid": TEST_KID,
                         "value": sign(TEST_PRIV, canonicalize(card))}
    return card


def regen() -> None:
    VECTOR_DIR.mkdir(parents=True, exist_ok=True)
    vectors = {
        "canon-basic.json": canonical_vector(),
        "did-valid.json": valid_did_doc(),
        "card-valid.json": valid_card(),
        "card-tampered.json": _tampered(valid_card()),
        "card-bad-alg.json": _with_signature(valid_card(), {"alg": "ES256",
                                                            "kid": TEST_KID,
                                                            "value": "AA"},
                                             expect="bad_alg"),
        "card-unknown-kid.json": _with_signature(
            valid_card(), {"alg": "Ed25519", "kid": DID + "#key-999", "value": "AA"},
            expect="key_not_found"),
        "card-key-not-in-assertion.json": _assertionless(valid_card()),
    }
    for name, vec in vectors.items():
        (VECTOR_DIR / name).write_text(
            json.dumps(vec, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {len(vectors)} vectors to {VECTOR_DIR}")


def _tampered(card: dict) -> dict:
    broken = json.loads(json.dumps(card))
    broken["name"] = "Tampered"
    return {"name": "card-tampered", "did_doc": valid_did_doc(),
            "card": broken, "expect": "bad_signature"}


def _with_signature(card: dict, sig: dict, expect: str) -> dict:
    broken = json.loads(json.dumps(card))
    broken["signature"] = sig
    return {"name": sig["alg"], "did_doc": valid_did_doc(),
            "card": broken, "expect": expect}


def _assertionless(card: dict) -> dict:
    did_doc = valid_did_doc()
    did_doc["assertionMethod"] = []
    broken = json.loads(json.dumps(card))
    return {"name": "card-key-not-in-assertion", "did_doc": did_doc,
            "card": broken, "expect": "key_not_in_assertion"}


def validate() -> int:
    failures = 0
    for path in sorted(VECTOR_DIR.glob("*.json")):
        vec = json.loads(path.read_text(encoding="utf-8"))
        name = vec.get("name", path.name)
        if "canonical" in vec:
            ok = canonicalize(vec["input"]) == vec["canonical"].encode("utf-8")
            print(f"{'PASS' if ok else 'FAIL'} {name} (canonicalization)")
            failures += 0 if ok else 1
        elif "expect" in vec:
            reason = verify_signature(vec["card"], vec["did_doc"])
            ok = reason == vec["expect"]
            print(f"{'PASS' if ok else 'FAIL'} {name} (expect {vec['expect']}, got {reason})")
            failures += 0 if ok else 1
        else:
            # did-valid.json / card-valid.json: structural sanity only
            ok = (vec.get("id") == DID or vec.get("agent_id") == DID)
            print(f"{'PASS' if ok else 'FAIL'} {name} (structure)")
            failures += 0 if ok else 1
    return 1 if failures else 0


if __name__ == "__main__":
    if "--regen" in sys.argv:
        regen()
    else:
        raise SystemExit(validate())
