"""shipcheck folder hygiene: no unresolved placeholders outside templates."""

import pathlib

import pytest

SHIPCHECK = pathlib.Path(__file__).resolve().parents[1] / "shipcheck"


@pytest.mark.skipif(not SHIPCHECK.exists(), reason="shipcheck not present")
def test_no_placeholder_domain_in_shipable_files():
    """'YOUR-DOMAIN' must not appear in anything shipable (public/, api/).

    Templates (*.template) are exempt: they are filled before deployment.
    """
    offenders = []
    for sub in ("public", "api", "requirements.txt"):
        p = SHIPCHECK / sub
        if p.is_file():
            files = [p]
        elif p.is_dir():
            files = sorted(x for x in p.rglob("*") if x.is_file())
        else:
            continue
        for f in files:
            if "YOUR-DOMAIN" in f.read_text(encoding="utf-8", errors="ignore"):
                offenders.append(str(f.relative_to(SHIPCHECK)))
    assert not offenders, f"unresolved placeholders in: {offenders}"
