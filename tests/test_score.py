"""Trust score tests with synthetic receipts."""

import datetime as dt

from tl.score import (client_base_weight, compute_score, recency_weight,
                      cap_weight)

NOW = dt.datetime(2026, 10, 3, tzinfo=dt.timezone.utc)


def ts(days_ago):
    return (NOW - dt.timedelta(days=days_ago)).isoformat()


def test_no_receipts_gives_neutral_prior():
    s = compute_score([], {})
    assert s["trust"] == 0.5
    assert s["confidence"] == 0.0


def test_all_successes_push_trust_up():
    receipts = [{"client_id": "did:web:a.org", "outcome": "success",
                 "timestamp": ts(1), "agent_id": "did:web:ag.com"}]
    s = compute_score(receipts, {}, now=NOW)
    assert s["trust"] > 0.5
    assert s["confidence"] > 0


def test_failures_pull_trust_down():
    good = [{"client_id": "did:web:a.org", "outcome": "success",
             "timestamp": ts(1), "agent_id": "ag"}]
    bad = [{"client_id": "did:web:a.org", "outcome": "failure",
            "timestamp": ts(1), "agent_id": "ag"}]
    up = compute_score(good, {}, now=NOW)["trust"]
    down = compute_score(bad, {}, now=NOW)["trust"]
    assert down < 0.5 < up


def test_old_receipts_matter_less():
    fresh = compute_score([{"client_id": "c", "outcome": "success",
                            "timestamp": ts(0), "agent_id": "a"}], {}, now=NOW)
    stale = compute_score([{"client_id": "c", "outcome": "success",
                            "timestamp": ts(360), "agent_id": "a"}], {}, now=NOW)
    assert fresh["trust"] > stale["trust"]


def test_per_client_cap_limits_egg_placement():
    one_client = [{"client_id": "did:web:one.org", "outcome": "success",
                   "timestamp": ts(1), "agent_id": "a"} for _ in range(50)]
    spread = [{"client_id": f"did:web:c{i}.org", "outcome": "success",
               "timestamp": ts(1), "agent_id": "a"} for i in range(50)]
    s1 = compute_score(one_client, {}, now=NOW)
    s2 = compute_score(spread, {}, now=NOW)
    assert s2["confidence"] > s1["confidence"]  # many clients = more evidence


def test_concentration_flag_and_cap():
    one_client = [{"client_id": "did:web:one.org", "outcome": "success",
                   "timestamp": ts(1), "agent_id": "a"} for _ in range(50)]
    s = compute_score(one_client, {}, now=NOW)
    assert s["concentration_flag"] is True


def test_client_weight_floor_and_age_tiers():
    assert client_base_weight(10) == 0.05
    assert client_base_weight(100) == 0.15
    assert client_base_weight(1000) == 0.30
    assert client_base_weight(None) == 0.05
    assert recency_weight(0) == 1.0
    assert 0 < recency_weight(90) < 1
    assert cap_weight(1) == 1.0
    assert cap_weight(4) == 0.5


def test_score_is_monotonic_in_success_weight():
    receipts = [{"client_id": f"did:web:c{i}.org", "outcome": "success",
                 "timestamp": ts(1), "agent_id": "a"} for i in range(5)]
    base = compute_score(receipts, {}, now=NOW)["trust"]
    more = compute_score(receipts + [{"client_id": "did:web:extra.org",
                                      "outcome": "success",
                                      "timestamp": ts(1), "agent_id": "a"}],
                         {}, now=NOW)["trust"]
    assert more >= base
