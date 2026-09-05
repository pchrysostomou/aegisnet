"""T-1.4 / T-1.5: oversized, pathologically nested and over-wide records are refused
before any parser can recurse into them, and long strings are capped, not stored whole."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from aegisnet.domain.enums import RejectReason
from aegisnet.domain.eve.limits import DEFAULT_LIMITS, ParseLimits
from aegisnet.domain.eve.normalizer import normalize_line
from aegisnet.domain.models import NormalizedEvent, Reject

pytestmark = pytest.mark.security

NOW = datetime(2026, 9, 5, 12, 0, tzinfo=UTC)
HEAD = '{"timestamp":"2026-09-01T10:00:00+0000","event_type":"flow"'


def _reason(line: str, limits: ParseLimits = DEFAULT_LIMITS) -> RejectReason:
    outcome = normalize_line(line, now=NOW, limits=limits)
    assert isinstance(outcome, Reject), outcome
    return outcome.reason


def test_a_line_over_the_byte_cap_is_refused_without_being_parsed() -> None:
    line = HEAD + ',"pad":"' + "x" * DEFAULT_LIMITS.max_line_bytes + '"}'
    assert _reason(line) is RejectReason.too_large


def test_multibyte_characters_count_as_bytes() -> None:
    line = HEAD + ',"pad":"' + "é" * (DEFAULT_LIMITS.max_line_bytes // 2) + '"}'
    assert _reason(line) is RejectReason.too_large


def test_deep_nesting_is_refused_by_the_scanner_not_by_a_recursion_error() -> None:
    depth = 20_000  # 40 KB: under the byte cap, far beyond Python's recursion limit
    line = HEAD + ',"deep":' + "[" * depth + "]" * depth + "}"
    assert len(line.encode()) < DEFAULT_LIMITS.max_line_bytes
    assert _reason(line) is RejectReason.too_deep


def test_nesting_just_over_the_limit_is_refused_and_at_the_limit_is_accepted() -> None:
    at_limit = HEAD + ',"deep":' + "[" * 11 + "]" * 11 + "}"  # object + 11 arrays = 12 levels
    assert isinstance(normalize_line(at_limit, now=NOW), NormalizedEvent)
    over = HEAD + ',"deep":' + "[" * 12 + "]" * 12 + "}"
    assert _reason(over) is RejectReason.too_deep


def test_brackets_inside_strings_do_not_count_as_nesting() -> None:
    line = HEAD + ',"note":"' + "[" * 500 + '"}'
    assert isinstance(normalize_line(line, now=NOW), NormalizedEvent)


def test_too_many_keys_or_items_are_refused_after_parsing() -> None:
    wide = json.loads(HEAD + "}")
    wide["wide"] = {f"k{i}": i for i in range(DEFAULT_LIMITS.max_keys_per_object + 1)}
    assert _reason(json.dumps(wide)) is RejectReason.too_large
    long = json.loads(HEAD + "}")
    long["items"] = list(range(DEFAULT_LIMITS.max_items_per_array + 1))
    assert _reason(json.dumps(long)) is RejectReason.too_large


def test_long_strings_are_capped_in_the_stored_payload_and_promoted_columns() -> None:
    hostname = "h" * 10_000
    line = json.dumps(
        {
            "timestamp": "2026-09-01T10:00:00+0000",
            "event_type": "http",
            "http": {"hostname": hostname, "url": "/" + "u" * 10_000},
        }
    )
    event = normalize_line(line, now=NOW)
    assert isinstance(event, NormalizedEvent)
    assert len(event.payload["http"]["hostname"]) == DEFAULT_LIMITS.max_string_chars
    assert event.http_host is not None and len(event.http_host) == 512
    assert event.http_url_path is not None and len(event.http_url_path) == 2048


def test_limits_are_enforced_in_order_size_then_depth_then_structure() -> None:
    tight = ParseLimits(max_line_bytes=200, max_json_depth=3, max_keys_per_object=3)
    assert _reason(HEAD + ',"pad":"' + "x" * 300 + '"}', tight) is RejectReason.too_large
    assert _reason(HEAD + ',"d":[[[[]]]]}', tight) is RejectReason.too_deep
    assert _reason(HEAD + ',"a":1,"b":2}', tight) is RejectReason.too_large
