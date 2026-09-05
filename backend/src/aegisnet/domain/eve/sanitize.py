"""Untrusted-text neutralisation for EVE content (THREAT_MODEL T-1.1).

Every string that arrives in an EVE record is attacker-influenceable: DNS names, HTTP
hosts and URLs, TLS SNI, file names, user agents. Before any of it is validated, stored or
logged, every C0 and C1 control character except tab is removed and the length is capped.
Tab survives because it is common in benign user agents and is harmless in JSON.

The same rule is applied by ``aegisnet.logging`` for log records; it is duplicated here
rather than imported so that the domain package stays free of infrastructure imports.
"""

from __future__ import annotations

import re
from typing import Any, Final

_CONTROL_CHARS: Final = re.compile(r"[\x00-\x08\x0a-\x1f\x7f-\x9f]")

MAX_STRING_CHARS: Final = 4096
"""Cap applied to every string value inside a record before validation."""

MAX_KEY_CHARS: Final = 128
"""Cap applied to every object key."""

EXCERPT_CHARS: Final = 256
"""Length of the sanitised head of a rejected line kept for debugging."""


def clean_text(value: str, max_chars: int = MAX_STRING_CHARS) -> str:
    """Strip control characters (except tab) and truncate to ``max_chars``."""
    cleaned = _CONTROL_CHARS.sub("", value)
    return cleaned[:max_chars] if len(cleaned) > max_chars else cleaned


def clean_json(value: object, *, max_chars: int = MAX_STRING_CHARS) -> object:
    """Recursively clean every string, including object keys, inside parsed JSON.

    Numbers, booleans and ``None`` pass through. Structural limits (depth, key counts)
    are enforced separately and earlier by :mod:`aegisnet.domain.eve.limits`.
    """
    if isinstance(value, str):
        return clean_text(value, max_chars)
    if isinstance(value, dict):
        return {
            clean_text(str(key), MAX_KEY_CHARS): clean_json(item, max_chars=max_chars)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [clean_json(item, max_chars=max_chars) for item in value]
    return value


def clean_record(record: dict[str, Any], *, max_chars: int = MAX_STRING_CHARS) -> dict[str, Any]:
    """:func:`clean_json` for a top-level object, keeping the ``dict`` type for callers."""
    cleaned = clean_json(record, max_chars=max_chars)
    if not isinstance(cleaned, dict):  # pragma: no cover - a dict always cleans to a dict
        raise TypeError("record must be a JSON object")
    return cleaned


def excerpt(raw: str, max_chars: int = EXCERPT_CHARS) -> str:
    """The sanitised head of a raw line, for ``ingest_rejects.raw_excerpt``."""
    return clean_text(raw, max_chars)
