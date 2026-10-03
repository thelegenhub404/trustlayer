"""CLI sign tests: --seed-env must produce the same signature as --seed-b64u."""

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tl.cli import main
from tl.keys import b64u_encode

CARD = {
    "spec_version": "trustlayer/0.2",
    "agent_id": "did:web:cli.example.com",
    "name": "CliAgent",
    "capabilities": [],
    "issued_at": "2026-01-01T00:00:00Z",
    "expires_at": "2027-01-01T00:00:00Z",
}


@pytest.fixture()
def seed_b64u():
    priv = Ed25519PrivateKey.generate()
    return b64u_encode(priv.private_bytes_raw())


def _sign(tmp_path, monkeypatch, capsys, seed_b64u, how):
    card_file = tmp_path / "trustlayer.json"
    card_file.write_text(json.dumps(CARD), encoding="utf-8")
    if how == "argv":
        argv = ["sign", str(card_file), "--seed-b64u", seed_b64u]
    elif how == "env":
        monkeypatch.setenv("TL_SEED", seed_b64u)
        argv = ["sign", str(card_file), "--seed-env", "TL_SEED"]
    else:  # file
        f = tmp_path / "seed.b64u"
        f.write_text(seed_b64u, encoding="ascii")
        argv = ["sign", str(card_file), "--seed-file", str(f)]
    buf_out, buf_err = capsys.readouterr()
    assert main(argv) == 0
    out, err = capsys.readouterr()
    signed = json.loads(out)
    return signed["signature"]["value"], signed["signature"]["kid"], err


def test_seed_env_matches_seed_argv(tmp_path, monkeypatch, capsys, seed_b64u):
    argv_sig, _, _ = _sign(tmp_path, monkeypatch, capsys, seed_b64u, "argv")
    env_sig, _, _ = _sign(tmp_path, monkeypatch, capsys, seed_b64u, "env")
    assert argv_sig == env_sig


def test_seed_file_matches_seed_argv(tmp_path, monkeypatch, capsys, seed_b64u):
    argv_sig, _, _ = _sign(tmp_path, monkeypatch, capsys, seed_b64u, "argv")
    file_sig, _, _ = _sign(tmp_path, monkeypatch, capsys, seed_b64u, "file")
    assert argv_sig == file_sig


def test_argv_seed_warns_but_env_does_not(tmp_path, monkeypatch, capsys, seed_b64u):
    _, _, err_argv = _sign(tmp_path, monkeypatch, capsys, seed_b64u, "argv")
    assert "shell history" in err_argv
    _, _, err_env = _sign(tmp_path, monkeypatch, capsys, seed_b64u, "env")
    assert "shell history" not in err_env


def test_missing_env_var_fails(tmp_path, monkeypatch, capsys):
    card_file = tmp_path / "trustlayer.json"
    card_file.write_text(json.dumps(CARD), encoding="utf-8")
    monkeypatch.delenv("TL_SEED_MISSING", raising=False)
    assert main(["sign", str(card_file), "--seed-env", "TL_SEED_MISSING"]) == 2


def test_keygen_warns_seed_shown_once(capsys):
    assert main(["keygen", "example.com"]) == 0
    out = capsys.readouterr().out
    assert "shown only this once" in out
