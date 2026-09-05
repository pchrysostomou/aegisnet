"""T-1.1: every string in a record is neutralised before validation, storage or logging."""

from __future__ import annotations

import pytest

from aegisnet.domain.eve.sanitize import (
    EXCERPT_CHARS,
    MAX_KEY_CHARS,
    MAX_STRING_CHARS,
    clean_json,
    clean_record,
    clean_text,
    excerpt,
)

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("plain.example.test", "plain.example.test"),
        ("a\x1b[31mred\x1b[0m", "a[31mred[0m"),
        ("line1\nline2\r\n", "line1line2"),
        ("nul\x00byte", "nulbyte"),
        ("c1\x85control\x9f", "c1control"),
        ("tab\tkept", "tab\tkept"),
        ("del\x7f", "del"),
        ("", ""),
    ],
)
def test_control_characters_except_tab_are_removed(raw: str, expected: str) -> None:
    assert clean_text(raw) == expected


def test_length_is_capped_after_cleaning() -> None:
    assert clean_text("x" * (MAX_STRING_CHARS + 50)) == "x" * MAX_STRING_CHARS
    assert clean_text("\n" * 10 + "abc", max_chars=2) == "ab"


def test_nested_structures_are_cleaned_including_keys() -> None:
    hostile = {
        "dns\n": {"rrname": "evil\x1b[2J.example.test", "answers": [{"rdata": "1.2.3.4\r"}]},
        "n": 3,
        "f": 1.5,
        "b": True,
        "z": None,
    }
    assert clean_json(hostile) == {
        "dns": {"rrname": "evil[2J.example.test", "answers": [{"rdata": "1.2.3.4"}]},
        "n": 3,
        "f": 1.5,
        "b": True,
        "z": None,
    }


def test_keys_are_capped_shorter_than_values() -> None:
    cleaned = clean_record({"k" * 500: "v" * 500})
    (key,) = cleaned
    assert len(key) == MAX_KEY_CHARS
    assert cleaned[key] == "v" * 500


def test_non_string_keys_become_strings() -> None:
    assert clean_json({1: "a"}) == {"1": "a"}


def test_excerpt_is_bounded_and_clean() -> None:
    raw = '{"dns":{"rrname":"\x1b[2J' + "a" * 1000 + '"}}'
    result = excerpt(raw)
    assert len(result) == EXCERPT_CHARS
    assert "\x1b" not in result
    assert result.startswith('{"dns":{"rrname":"[2J')
