"""Reproducibility tests for the crawler index."""

from crawler.build_index import build_index, write_data
from crawler.discover import load_seeds


def _sample_records():
    v = {"level": "L2",
         "checks": [{"name": "did_matches_host", "ok": True}],
         "red_flags": []}
    card = {"name": "WaterQualityBot", "description": "Water quality",
            "capabilities": [{"id": "water-quality-analysis",
                              "description": "NDCI/NDTI/CDOM"}]}
    return [{"agent_id": "did:web:b.com", "domain": "b.com", **v,
             "name": card["name"], "description": card["description"],
             "capabilities": card["capabilities"], "trust": None,
             "confidence": None, "score_version": "score/1"},
            {"agent_id": "did:web:a.com", "domain": "a.com", "level": "L1",
             "checks": [], "red_flags": [], "name": "a",
             "description": "", "capabilities": [], "trust": None,
             "confidence": None, "score_version": "score/1"}]


def test_index_is_deterministic():
    p1 = build_index(_sample_records())
    p2 = build_index(_sample_records())
    assert p1["index_hash"] == p2["index_hash"]
    assert p1["agents.json"] == p2["agents.json"]


def test_write_skips_when_unchanged(tmp_path):
    payload = build_index(_sample_records())
    assert write_data(payload, tmp_path, generated_at="2026-10-03T00:00:00Z")
    assert not write_data(payload, tmp_path, generated_at="2026-10-03T06:00:00Z")
    # a real change does rewrite
    records = _sample_records()
    records[0]["name"] = "Renamed"
    payload2 = build_index(records)
    assert write_data(payload2, tmp_path, generated_at="2026-10-03T07:00:00Z")


def test_seeds_parsing(tmp_path):
    f = tmp_path / "seeds.txt"
    f.write_text("# comment\n\nExample.COM\na.com\nExample.com\n")
    assert load_seeds(f) == ["a.com", "example.com"]


def test_seeds_reject_bad_domains(tmp_path):
    f = tmp_path / "seeds.txt"
    f.write_text("not a domain\n")
    try:
        load_seeds(f)
        assert False, "expected ValueError"
    except ValueError:
        pass
