"""GET /badge/{id} — SVG badge from the precomputed index (no live network).

Shows level + verification date, links back to nothing itself (the embedder
adds the link). The badge only proves what the agent page shows.
"""

from __future__ import annotations

import re
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from xml.sax.saxutils import escape

from api._lib.store import get_agent, meta

_ID_RE = re.compile(r"^did:web:[a-z0-9.%-]+$")

LEVEL_COLORS = {"L0": "#6B6A63", "L1": "#8A5A00", "L2": "#2F6B4F", "L3": "#1F5A41"}


_XML_ENTITIES = {'"': "&quot;", "'": "&#39;"}


def badge_svg(label: str, value: str, color: str) -> str:
    lw = 7 * len(label) + 20
    vw = 7 * len(value) + 20
    w = lw + vw
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="20" role="img" '
            f'aria-label="{escape(label, _XML_ENTITIES)}: {escape(value, _XML_ENTITIES)}">'
            f'<rect width="{lw}" height="20" fill="#141413"/>'
            f'<rect x="{lw}" width="{vw}" height="20" fill="{color}"/>'
            f'<g fill="#fff" font-family="Verdana,DejaVu Sans,sans-serif" font-size="11" text-anchor="middle">'
            f'<text x="{lw / 2}" y="14">{escape(label, _XML_ENTITIES)}</text>'
            f'<text x="{lw + vw / 2}" y="14">{escape(value, _XML_ENTITIES)}</text></g></svg>')


def handle(agent_id: str) -> tuple[int, str]:
    """Returns (http_status, svg_text)."""
    agent_id = (agent_id or "").strip()
    # Strict lowercase validation first: uppercase and odd chars are rejected,
    # not silently normalized.
    if not _ID_RE.match(agent_id):
        return 400, badge_svg("error", "invalid id", LEVEL_COLORS["L0"])
    agent_id = agent_id.lower()

    agent = get_agent(agent_id)
    if not agent:
        return 200, badge_svg("trustlayer", "not indexed", LEVEL_COLORS["L0"])

    level = agent.get("level", "L0")
    m = meta()
    verified_at = (m.get("generated_at") or "")[:10] or "unverified"
    color = LEVEL_COLORS.get(level, LEVEL_COLORS["L0"])
    return 200, badge_svg(level, verified_at, color)


class handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        q = parse_qs(urlparse(self.path).query)
        code, svg = handle((q.get("id") or [""])[0])
        self.send_response(code)
        self.send_header("Content-Type", "image/svg+xml")
        self.send_header("Cache-Control",
                         "public, s-maxage=3600, stale-while-revalidate=86400")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(svg.encode())

    def log_message(self, *args) -> None:
        pass
