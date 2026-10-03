"""Ed25519 keys: generation, fingerprint, JWK parsing and base64url helpers."""

from __future__ import annotations

import base64
import binascii
import hashlib
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def b64u_encode(data: bytes) -> str:
    """Base64url without padding (RFC 4648 section 5)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(s: str) -> bytes:
    """Decode base64url with or without padding."""
    if not isinstance(s, str):
        raise ValueError("base64url expected a string")
    pad = "=" * (-len(s) % 4)
    try:
        return base64.urlsafe_b64decode(s + pad)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"invalid base64url: {exc}") from exc


def generate_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Generate an Ed25519 keypair and return (private, public)."""
    priv = Ed25519PrivateKey.generate()
    return priv, priv.public_key()


def public_key_raw(pub: Ed25519PublicKey) -> bytes:
    """Raw bytes of the Ed25519 public key (32 bytes)."""
    raw = pub.public_bytes_raw()
    if len(raw) != 32:
        raise ValueError("Ed25519 public key must be 32 bytes")
    return raw


def fingerprint(pub: Ed25519PublicKey) -> str:
    """Key fingerprint: sha256:HEX over the 32 raw public key bytes.

    This is the value anchored in DNS TXT (_trustlayer.DOMAIN).
    """
    return "sha256:" + hashlib.sha256(public_key_raw(pub)).hexdigest()


def fingerprint_from_raw(raw: bytes) -> str:
    if len(raw) != 32:
        raise ValueError("expected 32 bytes of public key")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def to_jwk(pub: Ed25519PublicKey) -> dict[str, str]:
    """Serialize the public key as an OKP Ed25519 JWK (RFC 8037)."""
    return {"kty": "OKP", "crv": "Ed25519", "x": b64u_encode(public_key_raw(pub))}


def jwk_to_raw(jwk: dict[str, Any]) -> bytes:
    """Extract the 32 raw bytes from an OKP Ed25519 JWK, validating fields."""
    if not isinstance(jwk, dict):
        raise ValueError("invalid JWK")
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise ValueError("only OKP Ed25519 keys are accepted")
    x = jwk.get("x")
    if not isinstance(x, str):
        raise ValueError("JWK missing x field")
    raw = b64u_decode(x)
    if len(raw) != 32:
        raise ValueError("public key must be 32 bytes")
    return raw


def jwk_fingerprint(jwk: dict[str, Any]) -> str:
    """sha256 fingerprint of an Ed25519 JWK."""
    return fingerprint_from_raw(jwk_to_raw(jwk))


def sign(priv: Ed25519PrivateKey, message: bytes) -> str:
    """Sign bytes and return the signature as unpadded base64url."""
    return b64u_encode(priv.sign(message))
