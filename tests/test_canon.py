"""Canonicalization tests, including the official RFC 8785 Appendix examples."""

import json

import pytest

from tl.canon import canonicalize

# RFC 8785 B.1: literal example
RFC8785_B1_INPUT = json.loads(r"""
{
  "numbers": [333333333.33333329, 1E30, 4.50,
              2e-3, 0.000000000000000000000000001],
  "string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/",
  "literals": [null, true, false]
}
""")
RFC8785_B1_EXPECTED = (
    '{"literals":[null,true,false],"numbers":[333333333.3333333,'
    '1e+30,4.5,0.002,1e-27],"string":"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}'
).encode("utf-8")

# RFC 8785 B.2: character sorting (UTF-16 code unit order). Parsed via
# json.loads so the surrogate pair becomes a single code point.
RFC8785_B2_INPUT = json.loads(r'''{
  "\u20ac": "Euro Sign",
  "\r": "Carriage Return",
  "\ufb33": "Hebrew Letter Dalet With Dagesh",
  "1": "One",
  "\ud83d\ude00": "Emoji: Grinning Face",
  "\u0080": "Control",
  "\u00f6": "Latin Small Letter O With Diaeresis"
}''')
RFC8785_B2_EXPECTED = (
    '{"\\r":"Carriage Return","1":"One",'
    '"\x80":"Control","ö":"Latin Small Letter O With Diaeresis",'
    '"€":"Euro Sign","😀":"Emoji: Grinning Face",'
    '"דּ":"Hebrew Letter Dalet With Dagesh"}'
).encode("utf-8")


def test_rfc8785_b1_numbers_and_strings():
    assert canonicalize(RFC8785_B1_INPUT) == RFC8785_B1_EXPECTED


def test_rfc8785_b2_key_ordering():
    assert canonicalize(RFC8785_B2_INPUT) == RFC8785_B2_EXPECTED


def test_key_order_is_lexicographic_not_python_sorted():
    # "a" < "b" and UTF-16 order matches here; but ensure keys are sorted at all
    assert canonicalize({"b": 1, "a": 2}) == b'{"a":2,"b":1}'


def test_whitespace_is_irrelevant():
    a = json.loads('{"a": 1, "b": [2, 3]}')
    b = json.loads('{"b":[2,3],"a":1}')
    assert canonicalize(a) == canonicalize(b)


def test_invalid_types_rejected():
    with pytest.raises(TypeError):
        canonicalize({"x": object()})
    with pytest.raises(ValueError):
        canonicalize({"x": float("nan")})


def test_roundtrip_via_json():
    value = {"k": [1, "two", None, True], "z": 0, "a": -3}
    assert json.loads(canonicalize(value)) == value
