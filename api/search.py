"""GET /v1/search — BM25 over name, description and capabilities."""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

from api._lib.bm25 import BM25
from api._lib.store import agents, corpus, meta
from crawler.search_index import tokenize


def handle(query: dict[str, str]) -> tuple[int, dict]:
    q = query.get("q", "").strip()
    limit = min(max(int(query.get("limit", "20") or 20), 1), 100)
    offset = max(int(query.get("offset", "0") or 0), 0)
    min_level = query.get("min_level", "")
    min_trust = query.get("min_trust", "")
    min_confidence = query.get("min_confidence", "")
    capability = query.get("capability", "").lower()

    all_agents = agents()
    if q:
        bm25 = BM25(corpus())
        hits = bm25.search(tokenize(q), limit=len(all_agents))
        by_slug = {a["domain"].replace(".", "-"): a for a in all_agents}
        results = [by_slug[slug] for slug, _s in hits if slug in by_slug]
    else:
        results = sorted(all_agents, key=lambda a: a["domain"])

    level_rank = {"L0": 0, "L1": 1, "L2": 2, "L3": 3}
    if min_level:
        results = [a for a in results if level_rank.get(a["level"], 0)
                   >= level_rank.get(min_level, 0)]
    if capability:
        results = [a for a in results
                   if any(capability in (c.get("id", "").lower())
                          for c in a.get("capabilities", []))]
    if min_trust:
        try:
            tmin = float(min_trust)
            results = [a for a in results
                       if a.get("trust") is not None and a["trust"] >= tmin]
        except ValueError:
            pass
    if min_confidence:
        try:
            cmin = float(min_confidence)
            results = [a for a in results
                       if a.get("confidence") is not None and a["confidence"] >= cmin]
        except ValueError:
            pass

    # Relevance first; ties broken by level (higher wins).
    if q:
        hit_order = {slug: i for i, (slug, _s) in enumerate(
            BM25(corpus()).search(tokenize(q), limit=len(all_agents)))}
        results = sorted(results, key=lambda a: (
            hit_order.get(a["domain"].replace(".", "-"), 10**9),
            -{"L0": 0, "L1": 1, "L2": 2, "L3": 3}.get(a["level"], 0)))

    page = results[offset:offset + limit]
    m = meta()
    return 200, {
        "schema": "trustlayer.api/1",
        "index_generated_at": m.get("generated_at"),
        "score_version": m.get("score_version"),
        "total": len(results),
        "results": page,
    }


class handler(BaseHTTPRequestHandler):  # Vercel python runtime convention
    def do_GET(self) -> None:
        q = {k: v[0] for k, v in parse_qs(urlparse(self.path).query).items()}
        code, body = handle(q)
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(body, ensure_ascii=False).encode())

    def log_message(self, *args) -> None:  # keep function logs clean
        pass
