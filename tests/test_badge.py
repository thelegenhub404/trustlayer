"""Badge endpoint tests (pure, no network)."""

from api.badge import handle, badge_svg
from api import badge as badge_mod
from api._lib import store


def _with_index(monkeypatch, agents, meta):
    monkeypatch.setattr(store, "agents", lambda: agents, raising=False)
    monkeypatch.setattr(store, "meta", lambda: meta, raising=False)
    monkeypatch.setattr(badge_mod, "get_agent",
                        lambda aid: next((a for a in agents
                                          if a["agent_id"] == aid), None),
                        raising=False)


def test_snaypy_badge_shows_l2(monkeypatch):
    _with_index(monkeypatch,
                [{"agent_id": "did:web:snaypy.com", "level": "L2"}],
                {"generated_at": "2026-10-03T19:19:15+00:00"})
    code, svg = handle("did:web:snaypy.com")
    assert code == 200
    assert "L2" in svg and "2026-10-03" in svg and "<svg" in svg


def test_unknown_valid_id_not_indexed(monkeypatch):
    _with_index(monkeypatch, [], {"generated_at": None})
    code, svg = handle("did:web:unknown.example.com")
    assert code == 200
    assert "not indexed" in svg


def test_injection_ids_rejected():
    for bad in ("did:web:<script>", 'did:web:a"b', "did:web:a&b",
                "did:web:a b", "did:web:UPPER.com", "x; rm -rf"):
        code, _ = handle(bad)
        assert code == 400, bad


def test_xml_escaping(monkeypatch):
    # An agent whose level somehow contains markup must be escaped in the SVG.
    _with_index(monkeypatch,
                [{"agent_id": "did:web:evil.com", "level": 'L2"><script>'}],
                {"generated_at": None})
    code, svg = handle("did:web:evil.com")
    assert code == 200
    assert "<script>" not in svg
    assert "&lt;script&gt;" in svg


def test_svg_template_escapes_aria_label():
    svg = badge_svg('a"b', "x&y<c", "#000000")
    assert 'aria-label="a&quot;b: x&amp;y&lt;c"' in svg
