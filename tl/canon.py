"""JSON canonicalization per RFC 8785 (JSON Canonicalization Scheme, JCS).

Implementation covering the types used by TrustLayer: dict, list, str, bool,
None and int. Floats are serialized with the ECMAScript Number::toString rule
when they appear (TrustLayer avoids floats in signed data).

Do not add spaces or reorder keys manually: this function is the only
authorized path to produce signable bytes.
"""

from __future__ import annotations

import math
from typing import Any

# JCS escapes: C0 control chars are always escaped; everything else is left
# as-is (UTF-8 handles the rest during final serialization).
_ESCAPES = {
    0x08: "\\b",
    0x09: "\\t",
    0x0A: "\\n",
    0x0C: "\\f",
    0x0D: "\\r",
    0x22: '\\"',
    0x5C: "\\\\",
}


def _serialize_string(s: str) -> str:
    out = ['"']
    for ch in s:
        cp = ord(ch)
        esc = _ESCAPES.get(cp)
        if esc:
            out.append(esc)
        elif cp < 0x20:
            out.append(f"\\u{cp:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _serialize_number(n: float) -> str:
    if math.isnan(n) or math.isinf(n):
        raise ValueError("NaN and infinity are not canonical JSON")
    if n == 0:
        return "0"
    if n.is_integer() and abs(n) < 1e21:
        return str(int(n))
    # Python repr yields the shortest round-trip representation, which matches
    # ECMAScript Number::toString for the value ranges allowed in TrustLayer.
    s = repr(n)
    if "e" in s:
        mant, exp = s.split("e")
        exp = int(exp)
        if mant.endswith(".0"):
            mant = mant[:-2]
        if -7 < exp < 21:
            sign = "-" if mant.startswith("-") else ""
            digits = mant.lstrip("-").replace(".", "")
            point = mant.lstrip("-").find(".")
            point = len(mant.lstrip("-").split(".")[0]) if "." in mant.lstrip("-") else len(digits)
            pos = point + exp
            if pos <= 0:
                return f"{sign}0.{'0' * -pos}{digits}"
            if pos >= len(digits):
                return f"{sign}{digits + '0' * (pos - len(digits))}"
            return f"{sign}{digits[:pos]}.{digits[pos:]}"
        # ECMAScript always emits a sign in the exponent: 1e+30, 1e-7.
        e_char = "e+" if exp > 0 else "e-"
        return f"{mant}{e_char}{abs(exp)}"
    return s


def _serialize(value: Any, out: list[str]) -> None:
    if value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif value is None:
        out.append("null")
    elif isinstance(value, str):
        out.append(_serialize_string(value))
    elif isinstance(value, int):
        out.append(str(value))
    elif isinstance(value, float):
        out.append(_serialize_number(value))
    elif isinstance(value, (list, tuple)):
        out.append("[")
        for i, item in enumerate(value):
            if i:
                out.append(",")
            _serialize(item, out)
        out.append("]")
    elif isinstance(value, dict):
        # Keys sorted by UTF-16 code units (RFC 8785, section 3.2.3). Within
        # the BMP this matches code point order; outside it, surrogate pairs
        # matter, hence sorting by UTF-16BE encoding.
        items = sorted(value.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        out.append("{")
        for i, (k, v) in enumerate(items):
            if i:
                out.append(",")
            out.append(_serialize_string(k))
            out.append(":")
            _serialize(v, out)
        out.append("}")
    else:
        raise TypeError(f"type not serializable under JCS: {type(value)!r}")


def canonicalize(value: Any) -> bytes:
    """Return the RFC 8785 canonical UTF-8 bytes of *value*."""
    out: list[str] = []
    _serialize(value, out)
    # surrogatepass keeps lone surrogates from crashing; RFC 8785 considers
    # such JSON invalid, so callers signing it get deterministic bytes anyway.
    return "".join(out).encode("utf-8", "surrogatepass")
