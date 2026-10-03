"""Trust score, version score/1 (plan section 8).

Two numbers: trust (Bayesian reputation) and confidence (0-1). Only computed
for agents at L2 or above. Changing the formula requires a PR and a version
bump.
"""

from __future__ import annotations

import datetime as dt
import math
from typing import Any

SCORE_VERSION = "score/1"
HALF_LIFE_DAYS = 90.0
MAX_PER_CLIENT_PER_AGENT_PER_DAY = 100
CONCENTRATION_LIMIT = 0.60
CONCENTRATION_CAP = 0.30

# Prior beta(2.5, 2.5): no data -> rep = 0.5
ALPHA0 = 2.5
BETA0 = 2.5

# Domain age -> client base weight (RDAP, fetched by the crawler)
CLIENT_BASE_WEIGHTS = ((30, 0.05), (365, 0.15))


def client_base_weight(domain_age_days: int | None) -> float:
    """Base weight from domain age: <30d -> 0.05, <1y -> 0.15, else 0.30."""
    if domain_age_days is None:
        return 0.05
    for limit, w in CLIENT_BASE_WEIGHTS:
        if domain_age_days < limit:
            return w
    return 0.30


def recency_weight(receipt_age_days: float) -> float:
    """w_age = 0.5^(days/90): 90-day half-life."""
    return 0.5 ** (max(receipt_age_days, 0.0) / HALF_LIFE_DAYS)


def cap_weight(n_previous_same_client: int) -> float:
    """w_cap = 1/sqrt(n) over the client's previous receipts for the same agent."""
    return 1.0 / math.sqrt(max(n_previous_same_client, 1))


def compute_score(receipts: list[dict[str, Any]], client_weights: dict[str, float],
                  *, now: dt.datetime | None = None) -> dict[str, Any]:
    """Compute trust and confidence from already-validated receipts.

    receipts: [{client_id, outcome, timestamp}] (ISO-8601 timestamps).
    client_weights: {client_id: reputation weight (0.05 minimum)}.
    """
    now = now or dt.datetime.now(dt.timezone.utc)
    success_w = 0.0
    total_w = 0.0
    per_client: dict[str, float] = {}
    counts: dict[tuple[str, str], int] = {}

    for r in receipts:
        client = r.get("client_id", "")
        if not isinstance(client, str) or not client:
            continue
        w_client = max(client_weights.get(client, 0.05), 0.05)
        ts = r.get("timestamp")
        days = 0.0
        if isinstance(ts, str):
            try:
                t = dt.datetime.fromisoformat(ts.replace("Z", "+00:00"))
                days = max((now - t).total_seconds() / 86400.0, 0.0)
            except ValueError:
                pass
        key = (client, r.get("agent_id", ""))
        n = counts.get(key, 0)
        counts[key] = n + 1
        w = w_client * recency_weight(days) * cap_weight(n)
        total_w += w
        per_client[client] = per_client.get(client, 0.0) + w
        if r.get("outcome") == "success":
            success_w += w

    # Concentration: a single client over 60% of the weight gets capped at 30%.
    # (eTLD+1 segmentation is done by the crawler; per-client here.)
    concentration_flag = False
    if total_w > 0:
        top = max(per_client.values())
        if top / total_w > CONCENTRATION_LIMIT:
            concentration_flag = True
            excess = top - CONCENTRATION_CAP * total_w
            if excess > 0:
                scale = (total_w - excess) / total_w
                success_w *= scale
                total_w *= scale

    rep = (success_w + ALPHA0) / (total_w + ALPHA0 + BETA0)
    confidence = 1.0 - math.exp(-total_w / 20.0)
    return {
        "trust": round(rep, 4),
        "confidence": round(confidence, 4),
        "n_receipts": len(receipts),
        "effective_weight": round(total_w, 4),
        "concentration_flag": concentration_flag,
        "score_version": SCORE_VERSION,
    }
