"""GET /v1/agents/{did} — agent record with verification breakdown."""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse, unquote

from api._lib.store import get_agent, meta


def handle(agent_id: str) -> tuple[int, dict]:
    agent = get_agent(unquote(agent_id))
    m = meta()
    if not agent:
        return 404, {"error": {"code": "not_found",
                               "message": "Agent not indexed"}}
    return 200, {
        "schema": "trustlayer.api/1",
        "index_generated_at": m.get("generated_at"),
        "score_version": m.get("score_version"),
        **agent,
    }


class handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        parts = urlparse(self.path)
        agent_id = unquote(parts.path.split("/v1/agents/", 1)[-1].split("/")[0])
        code, body = handle(agent_id)
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(body, ensure_ascii=False).encode())

    def log_message(self, *args) -> None:
        pass
