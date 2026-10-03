"""Shipcheck demo agent endpoint (Vercel python function).

POST/GET /api/run (rewritten as /v1/run) — responds with a small JSON body
and, when the client sends TrustLayer-Nonce, a co-signed TrustLayer-Delivery
header (SPEC v0.2.1 section 7).

Environment (set in the Vercel dashboard, encrypted):
- TL_DELIVERY_SEED: base64url Ed25519 seed for the #delivery-1 key.
- SHIPCHECK_DOMAIN: the agent's host, e.g. shipcheck.example.com.

Never logs the seed.
"""

from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

from tl import delivery
from tl.keys import b64u_decode
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _seed_from_env() -> Ed25519PrivateKey | None:
    raw = os.environ.get("TL_DELIVERY_SEED", "")
    if not raw:
        return None
    try:
        return Ed25519PrivateKey.from_private_bytes(b64u_decode(raw))
    except ValueError:
        return None


def handle(method: str, query: dict[str, str],
           nonce: str | None, task_hash: str | None) -> tuple[int, bytes, dict[str, str]]:
    domain = (os.environ.get("SHIPCHECK_DOMAIN") or "shipcheck.example.com").lower()
    agent_id = f"did:web:{domain}"
    capability_id = "shipment-status"

    body = json.dumps({
        "capability": capability_id,
        "shipment": query.get("id", "unknown"),
        "status": "in_transit",
    }, separators=(",", ":")).encode()

    headers = {"Content-Type": "application/json",
               "Access-Control-Allow-Origin": "*"}

    # Optional co-signed delivery: only when the client sent a nonce.
    if nonce is not None:
        try:
            delivery.validate_request(nonce, task_hash)
        except delivery.DeliveryError as exc:
            return 400, json.dumps(
                {"error": {"code": "invalid_delivery_request",
                           "message": str(exc)}},
                separators=(",", ":")).encode(), headers
        priv = _seed_from_env()
        if priv is None:
            return 500, json.dumps(
                {"error": {"code": "delivery_key_missing",
                           "message": "TL_DELIVERY_SEED is not configured"}},
                separators=(",", ":")).encode(), headers
        d = delivery.make_delivery(
            priv=priv, kid=f"{agent_id}#delivery-1", agent_id=agent_id,
            capability_id=capability_id, nonce=nonce,
            task_hash=(task_hash or "").lower(), body=body)
        headers.update(delivery.delivery_response_headers(d))

    return 200, body, headers


class handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        q = {k: v[0] for k, v in parse_qs(urlparse(self.path).query).items()}
        nonce = self.headers.get("TrustLayer-Nonce")
        code, body, headers = handle(
            "GET", q, nonce, self.headers.get("TrustLayer-Task-Hash"))
        self.send_response(code)
        for k, v in headers.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    do_POST = do_GET

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers",
                         "TrustLayer-Nonce, TrustLayer-Task-Hash")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()

    def log_message(self, *args) -> None:
        pass
