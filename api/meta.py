"""GET /v1/index/meta — index hash, score version and counts."""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler

from api._lib.store import meta


def handle() -> tuple[int, dict]:
    m = meta()
    return 200, {
        "schema": "trustlayer.api/1",
        **m,
    }


class handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        code, body = handle()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(body, ensure_ascii=False).encode())

    def log_message(self, *args) -> None:
        pass
