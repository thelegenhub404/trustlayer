"""Key handling tests: fingerprints, JWK round-trips, b64url."""

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tl.keys import (b64u_decode, b64u_encode, fingerprint, jwk_fingerprint,
                     jwk_to_raw, public_key_raw, to_jwk)


def test_b64u_roundtrip_no_padding():
    data = bytes(range(64))
    enc = b64u_encode(data)
    assert "=" not in enc
    assert b64u_decode(enc) == data


def test_b64u_decode_accepts_padding():
    import base64
    assert b64u_decode(base64.urlsafe_b64encode(b"hi").decode()) == b"hi"


def test_fingerprint_is_deterministic_sha256():
    priv = Ed25519PrivateKey.generate()
    fp = fingerprint(priv.public_key())
    assert fp.startswith("sha256:") and len(fp) == 7 + 64
    assert fingerprint(priv.public_key()) == fp


def test_jwk_roundtrip():
    priv = Ed25519PrivateKey.generate()
    jwk = to_jwk(priv.public_key())
    assert jwk == {"kty": "OKP", "crv": "Ed25519", "x": jwk["x"]}
    assert jwk_to_raw(jwk) == public_key_raw(priv.public_key())
    assert jwk_fingerprint(jwk) == fingerprint(priv.public_key())


def test_jwk_rejects_wrong_key_type():
    with pytest.raises(ValueError):
        jwk_to_raw({"kty": "EC", "crv": "P-256", "x": "AA"})
    with pytest.raises(ValueError):
        jwk_to_raw({"kty": "OKP", "crv": "X25519", "x": b64u_encode(b"\x01" * 32)})
    with pytest.raises(ValueError):
        jwk_to_raw({"kty": "OKP", "crv": "Ed25519", "x": b64u_encode(b"\x01" * 31)})
