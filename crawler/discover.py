"""Seed handling and agent discovery helpers.

Phase 1: seeds.txt is the only entry point. Public A2A/MCP registries can be
added later; they enter as L0 until verified.
"""

from __future__ import annotations

import re
from pathlib import Path

_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def load_seeds(path: str | Path) -> list[str]:
    """Read seeds.txt: one domain per line, comments (#) and blanks skipped."""
    seeds: list[str] = []
    for raw in Path(path).read_text(encoding="utf-8").splitlines():
        line = raw.strip().lower().rstrip(".")
        if not line or line.startswith("#"):
            continue
        if not _DOMAIN_RE.match(line):
            raise ValueError(f"invalid domain in seeds file: {raw!r}")
        seeds.append(line)
    # Deterministic order: reproducibility first.
    return sorted(set(seeds))
