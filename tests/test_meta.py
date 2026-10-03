"""Index meta / counts tests."""

from crawler.build_index import build_index

from api.meta import handle
from api import meta as meta_mod
from api._lib import store


def _records():
    def rec(domain, level):
        return {"agent_id": f"did:web:{domain}", "domain": domain,
                "level": level, "checks": [], "red_flags": [], "name": domain,
                "description": "", "capabilities": [], "trust": None,
                "confidence": None, "score_version": "score/1"}
    return [rec("a.com", "L1"), rec("b.com", "L2"), rec("c.com", "L2"),
            rec("d.com", "L3"), rec("e.com", "L0")]


def test_counts_match_agents():
    payload = build_index(_records())
    assert payload["agents.json"][0]["domain"] == "a.com"  # sorted
    # counts are computed inside write_data; replicate via its helper path:
    counts = {"indexed": 5, "l1": 1, "l2": 2, "l3": 1}
    import tempfile
    import pathlib
    import json
    with tempfile.TemporaryDirectory() as d:
        from crawler.build_index import write_data
        write_data(payload, d, generated_at="2026-10-03T00:00:00Z")
        meta = json.loads((pathlib.Path(d) / "meta.json").read_text(encoding="utf-8"))
    assert meta["counts"] == counts


def test_meta_endpoint_shape(monkeypatch):
    monkeypatch.setattr(store, "meta", lambda: {
        "index_hash": "sha256:abc", "score_version": "score/1",
        "n_agents": 1, "counts": {"indexed": 1, "l1": 0, "l2": 1, "l3": 0},
        "generated_at": "2026-10-03T00:00:00+00:00"}, raising=False)
    monkeypatch.setattr(meta_mod, "meta", store.meta, raising=False)
    code, body = handle()
    assert code == 200
    assert body["schema"] == "trustlayer.api/1"
    assert body["counts"]["l2"] == 1
