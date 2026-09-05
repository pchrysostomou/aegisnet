"""Structural limits: size, depth, key and item counts (T-1.4, T-1.5)."""

from __future__ import annotations

import pytest

from aegisnet.domain.enums import RejectReason
from aegisnet.domain.eve.limits import (
    DEFAULT_LIMITS,
    ParseLimits,
    bracket_depth,
    encoded_size,
    structure_violation,
)

pytestmark = pytest.mark.unit


def test_encoded_size_counts_utf8_bytes_not_characters() -> None:
    assert encoded_size("abc") == 3
    assert encoded_size("é") == 2
    assert encoded_size("😀") == 4


@pytest.mark.parametrize(
    ("text", "depth"),
    [
        ("", 0),
        ("{}", 1),
        ('{"a": {"b": [1, {"c": 2}]}}', 4),
        ('{"s": "{[[[[[[["}', 1),
        ('{"s": "\\"{[", "t": [1]}', 2),
        ("[[[", 3),
        ("}}}{", 1),
    ],
)
def test_bracket_depth_ignores_brackets_inside_strings(text: str, depth: int) -> None:
    assert bracket_depth(text) == depth


def test_bracket_depth_stops_scanning_once_the_limit_is_passed() -> None:
    hostile = "[" * 1_000_000
    assert bracket_depth(hostile, stop_above=12) == 13


def test_default_limits_match_the_api_contract() -> None:
    assert (
        ParseLimits(
            max_line_bytes=65_536,
            max_json_depth=12,
            max_keys_per_object=200,
            max_items_per_array=1000,
            max_string_chars=4096,
        )
        == DEFAULT_LIMITS
    )


def test_structure_within_limits_is_accepted() -> None:
    nested: dict[str, object] = {"k": "v"}
    for _ in range(DEFAULT_LIMITS.max_json_depth - 1):
        nested = {"n": nested}
    assert structure_violation(nested) is None
    assert structure_violation({"keys": {f"k{i}": i for i in range(200)}}) is None
    assert structure_violation({"items": list(range(1000))}) is None


def test_too_deep_is_reported_for_objects_and_arrays() -> None:
    nested: object = {"k": "v"}
    for _ in range(DEFAULT_LIMITS.max_json_depth):
        nested = {"n": nested}
    assert structure_violation(nested) is RejectReason.too_deep

    arrays: object = [1]
    for _ in range(DEFAULT_LIMITS.max_json_depth):
        arrays = [arrays]
    assert structure_violation(arrays) is RejectReason.too_deep


def test_too_large_is_reported_for_wide_objects_and_long_arrays() -> None:
    assert structure_violation({f"k{i}": i for i in range(201)}) is RejectReason.too_large
    assert structure_violation({"a": list(range(1001))}) is RejectReason.too_large


def test_limits_are_configurable() -> None:
    tight = ParseLimits(max_json_depth=2, max_keys_per_object=1, max_items_per_array=1)
    assert structure_violation({"a": {"b": {"c": 1}}}, tight) is RejectReason.too_deep
    assert structure_violation({"a": 1, "b": 2}, tight) is RejectReason.too_large
    assert structure_violation({"a": [1, 2]}, tight) is RejectReason.too_large
