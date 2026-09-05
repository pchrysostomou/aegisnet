"""Keyset pagination cursors and limits (T-2.6: every list is bounded).

A cursor is the base64url of a small JSON array; it names the last row seen, never an
offset, so pages are stable while rows are added. Cursors are opaque to callers and are
validated strictly when they come back: anything malformed raises
:class:`InvalidCursorError`, which the API maps to a validation failure.
"""

from __future__ import annotations

import base64
import binascii
import json
from datetime import datetime
from typing import Final
from uuid import UUID

DEFAULT_LIMIT: Final = 50
MAX_LIMIT: Final = 200
MAX_CURSOR_CHARS: Final = 256


class InvalidCursorError(ValueError):
    pass


def check_limit(limit: int) -> int:
    if not 1 <= limit <= MAX_LIMIT:
        raise ValueError(f"limit must be between 1 and {MAX_LIMIT}")
    return limit


def _encode(parts: list[str]) -> str:
    raw = json.dumps(parts, separators=(",", ":")).encode("ascii")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _decode(cursor: str, expected: int) -> list[str]:
    if not cursor or len(cursor) > MAX_CURSOR_CHARS:
        raise InvalidCursorError("cursor is malformed")
    padded = cursor + "=" * (-len(cursor) % 4)
    try:
        parts = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")))
    except (binascii.Error, ValueError, UnicodeError) as error:
        raise InvalidCursorError("cursor is malformed") from error
    if (
        not isinstance(parts, list)
        or len(parts) != expected
        or not all(isinstance(part, str) for part in parts)
    ):
        raise InvalidCursorError("cursor is malformed")
    return parts


def encode_time_id(moment: datetime, row_id: UUID) -> str:
    if moment.tzinfo is None:
        raise ValueError("cursor timestamps must be timezone-aware")
    return _encode([moment.isoformat(timespec="microseconds"), str(row_id)])


def decode_time_id(cursor: str) -> tuple[datetime, UUID]:
    stamp, row_id = _decode(cursor, 2)
    try:
        moment = datetime.fromisoformat(stamp)
        identifier = UUID(row_id)
    except ValueError as error:
        raise InvalidCursorError("cursor is malformed") from error
    if moment.tzinfo is None:
        raise InvalidCursorError("cursor is malformed")
    return moment, identifier


def encode_int(value: int) -> str:
    return _encode([str(value)])


def decode_int(cursor: str) -> int:
    (raw,) = _decode(cursor, 1)
    if not raw.isdigit():
        raise InvalidCursorError("cursor is malformed")
    return int(raw)
