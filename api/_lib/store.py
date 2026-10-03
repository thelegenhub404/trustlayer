"""Loads data/ once per instance. Vercel functions are read-only."""

from __future__ import annotations

import json
import os
import pathlib
from typing import Any

_data_dir = pathlib.Path(__file__).resolve().parents[2] / "data"

_cache: dict[str, Any] = {}


def _load(name: str) -> Any:
    if name not in _cache:
        path = _data_dir / name
        _cache[name] = json.loads(path.read_text(encoding="utf-8"))
    return _cache[name]


def _from_raw_github(name: str) -> Any:
    """Fallback: fetch from raw.githubusercontent.com (see vercel.json notes)."""
    import urllib.request

    repo = os.environ.get("TL_RAW_REPO", "")
    branch = os.environ.get("TL_RAW_BRANCH", "main")
    url = f"https://raw.githubusercontent.com/{repo}/{branch}/data/{name}"
    with urllib.request.urlopen(url, timeout=10) as resp:  # noqa: S310 (fixed host)
        _cache[name] = json.loads(resp.read().decode("utf-8"))
    return _cache[name]


def agents() -> list[dict[str, Any]]:
    try:
        return _load("agents.json")
    except FileNotFoundError:
        if os.environ.get("TL_RAW_REPO"):
            return _from_raw_github("agents.json")
        return []


def corpus() -> dict[str, list[str]]:
    try:
        return _load("corpus.json")
    except FileNotFoundError:
        if os.environ.get("TL_RAW_REPO"):
            return _from_raw_github("corpus.json")
        return {}


def meta() -> dict[str, Any]:
    try:
        return _load("meta.json")
    except FileNotFoundError:
        return {"index_hash": None, "score_version": "score/1", "n_agents": 0,
                "generated_at": None}


def get_agent(agent_id: str) -> dict[str, Any] | None:
    for a in agents():
        if a["agent_id"] == agent_id or a["domain"] == agent_id:
            return a
    return None
