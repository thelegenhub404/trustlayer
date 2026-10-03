"""GET /v1/verify?agent_id= — precomputed verification result."""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

from api._lib.store import get_agent, meta


def handle(agent_id: str) -> tuple[int, dict]:
    m = meta()
    agent = get_agent(agent_id)
    if not agent:
        return 404, {"error": {"code": "not_found",
                               "message": "Agent not indexed"}}
    return 200, {
        "schema": "trustlayer.api/1",
        "index_generated_at": m.get("generated_at"),
        "score_version": m.get("score_version"),
        "agent_id": agent["agent_id"],
        "domain": agent["domain"],
        "level": agent["level"],
        "checks": agent["checks"],
        "red_flags": agent["red_flags"],
        "trust": agent.get("trust"),
        "confidence": agent.get("confidence"),
        "verified_at": m.get("generated_at"),
    }


class handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        q = parse_qs(urlparse(self.path).query)
        code, body = handle((q.get("agent_id") or [""])[0])
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(body, ensure_ascii=False).encode())

    def log_message(self, *args) -> None:
        pass
