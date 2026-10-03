"""Tokenization for BM25. Shared by the crawler (build time) and the API."""

from __future__ import annotations

import re
import unicodedata

_TOKEN_RE = re.compile(r"[a-z0-9]+")


def tokenize(text: str) -> list[str]:
    """Lowercase, strip accents and split on non-alphanumerics."""
    text = unicodedata.normalize("NFKD", text or "")
    text = "".join(c for c in text if not unicodedata.combining(c))
    return _TOKEN_RE.findall(text.lower())


def document_text(agent: dict) -> str:
    """Concatenate the searchable fields of an agent record."""
    parts = [agent.get("name", ""), agent.get("description", "")]
    for cap in agent.get("capabilities", []) or []:
        parts.append(cap.get("id", ""))
        parts.append(cap.get("description", ""))
    return " ".join(parts)
