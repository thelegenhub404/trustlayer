"""Build the reproducible index: agents.json, agents/{slug}.json, meta.json.

Reproducibility rules:
- agents.json is a sorted array; every agent record is deterministic;
- generated_at lives only in meta.json;
- index_hash covers agents.json + per-agent files, with timestamps excluded;
- the caller must not write anything when the hash is unchanged.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
from typing import Any

from .search_index import document_text, tokenize

DATA_DIR = pathlib.Path("data")


def _stable(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def build_agent_record(domain: str, verification: dict[str, Any],
                       card: dict[str, Any] | None,
                       score: dict[str, Any] | None) -> dict[str, Any]:
    """Assemble the public record for one agent."""
    record = {
        "agent_id": f"did:web:{domain}",
        "domain": domain,
        "level": verification["level"],
        "checks": verification["checks"],
        "red_flags": verification["red_flags"],
        "name": (card or {}).get("name") or domain,
        "description": (card or {}).get("description", ""),
        "capabilities": [
            {
                "id": c.get("id", ""),
                "description": c.get("description", ""),
                "endpoint": c.get("endpoint", ""),
                "payment": c.get("payment", {"method": "none"}),
                "pricing": c.get("pricing"),
                "data_handling": c.get("data_handling"),
            }
            for c in (card or {}).get("capabilities", []) or []
        ],
        "trust": (score or {}).get("trust"),
        "confidence": (score or {}).get("confidence"),
        "score_version": (score or {}).get("score_version", "score/1"),
    }
    return record


def slug_for(domain: str) -> str:
    return domain.replace(".", "-")


def build_index(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Produce the full data/ payload from sorted agent records."""
    records = sorted(records, key=lambda r: r["domain"])
    agents_json = records
    per_agent = {slug_for(r["domain"]): r for r in records}
    # BM25 corpus is precomputed at build time; the API only scores queries.
    corpus = {slug_for(r["domain"]): tokenize(document_text(r)) for r in records}
    payload = {
        "agents.json": agents_json,
        "agents": per_agent,
        "corpus": corpus,
    }
    hash_src = _stable({"agents": agents_json, "corpus": corpus})
    payload["index_hash"] = "sha256:" + hashlib.sha256(hash_src.encode("utf-8")).hexdigest()
    return payload


def write_data(payload: dict[str, Any], out_dir: str | pathlib.Path = DATA_DIR,
               generated_at: str | None = None) -> bool:
    """Write data/ only if content changed. Returns True if files changed."""
    out = pathlib.Path(out_dir)
    meta_path = out / "meta.json"
    old_meta: dict[str, Any] = {}
    if meta_path.exists():
        try:
            old_meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except ValueError:
            old_meta = {}
    counts = {"indexed": len(payload["agents.json"]), "l1": 0, "l2": 0, "l3": 0}
    for r in payload["agents.json"]:
        level = (r.get("level") or "L0").lower()
        if level in counts:
            counts[level] += 1
    if (old_meta.get("index_hash") == payload["index_hash"]
            and old_meta.get("counts") == counts):
        return False  # nothing changed: no commit, no redeploy

    out.mkdir(parents=True, exist_ok=True)
    (out / "agents.json").write_text(
        json.dumps(payload["agents.json"], indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8")
    agents_dir = out / "agents"
    agents_dir.mkdir(exist_ok=True)
    for slug, record in payload["agents"].items():
        (agents_dir / f"{slug}.json").write_text(
            json.dumps(record, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (out / "corpus.json").write_text(
        json.dumps(payload["corpus"], ensure_ascii=False), encoding="utf-8")
    meta = {
        "index_hash": payload["index_hash"],
        "score_version": "score/1",
        "n_agents": len(payload["agents.json"]),
        "counts": counts,
        "generated_at": generated_at,
    }
    meta_path.write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    return True
