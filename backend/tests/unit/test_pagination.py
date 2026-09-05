"""Cursors are opaque, round-trip exactly, and refuse anything tampered (T-2.6)."""

from __future__ import annotations

import base64
from datetime import UTC, datetime
from uuid import UUID

import pytest

from aegisnet.domain.pagination import (
    MAX_LIMIT,
    InvalidCursorError,
    check_limit,
    decode_int,
    decode_time_id,
    encode_int,
    encode_time_id,
)

pytestmark = pytest.mark.unit

MOMENT = datetime(2026, 9, 1, 10, 0, 0, 123456, tzinfo=UTC)
ROW = UUID("11111111-2222-3333-4444-555555555555")


def test_time_id_cursor_round_trips_and_is_url_safe() -> None:
    cursor = encode_time_id(MOMENT, ROW)
    assert "=" not in cursor and "+" not in cursor and "/" not in cursor
    assert decode_time_id(cursor) == (MOMENT, ROW)


def test_int_cursor_round_trips() -> None:
    assert decode_int(encode_int(4242)) == 4242


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "not-base64!!",
        base64.urlsafe_b64encode(b"[]").decode(),
        base64.urlsafe_b64encode(b'["only-one"]').decode(),
        base64.urlsafe_b64encode(b'["2026-09-01T10:00:00", "x"]').decode(),
        base64.urlsafe_b64encode(b'["2026-09-01T10:00:00+00:00", "not-a-uuid"]').decode(),
        base64.urlsafe_b64encode(b'{"a": 1}').decode(),
        base64.urlsafe_b64encode(b"[1, 2]").decode(),
        "x" * 300,
    ],
)
def test_tampered_time_id_cursors_are_refused(bad: str) -> None:
    with pytest.raises(InvalidCursorError):
        decode_time_id(bad)


@pytest.mark.parametrize("bad", ["", base64.urlsafe_b64encode(b'["-1"]').decode(), "zzz"])
def test_tampered_int_cursors_are_refused(bad: str) -> None:
    with pytest.raises(InvalidCursorError):
        decode_int(bad)


def test_naive_timestamps_cannot_become_cursors() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        encode_time_id(datetime(2026, 9, 1), ROW)


@pytest.mark.parametrize("limit", [0, -1, MAX_LIMIT + 1])
def test_limits_outside_the_bounds_are_refused(limit: int) -> None:
    with pytest.raises(ValueError, match="between 1 and"):
        check_limit(limit)


def test_limits_inside_the_bounds_pass_through() -> None:
    assert check_limit(1) == 1 and check_limit(MAX_LIMIT) == MAX_LIMIT
