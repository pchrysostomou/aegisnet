"""One EVE line in, a :class:`NormalizedEvent` or a :class:`Reject` out.

Order of operations, each step refusing before the next can be reached:

1. byte-length cap (``too_large``);
2. bracket-depth scan of the raw text (``too_deep``);
3. ``json.loads`` (``json_parse``); the top level must be an object (``schema_invalid``);
4. structural walk: depth, key and item counts (``too_deep`` / ``too_large``);
5. sanitisation of every string and key (T-1.1);
6. schema validation (``missing_required`` for ``timestamp``/``event_type``, otherwise
   ``schema_invalid``);
7. ``event_type`` triage (``unsupported_event_type`` for Suricata housekeeping records);
8. timestamp sanity window (``timestamp_out_of_range``, T-1.7);
9. canonical hash, promotion of the typed columns, and the sanitised payload.

The clock is a parameter, never read here, so every path is deterministic in tests.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Final

from pydantic import ValidationError

from aegisnet.domain.enums import EventType, RejectReason
from aegisnet.domain.eve.hashing import event_hash, hash_material
from aegisnet.domain.eve.limits import (
    DEFAULT_LIMITS,
    ParseLimits,
    bracket_depth,
    encoded_size,
    structure_violation,
)
from aegisnet.domain.eve.sanitize import clean_record, clean_text, excerpt
from aegisnet.domain.eve.schema import DnsInfo, EveRecord
from aegisnet.domain.models import NormalizedEvent, Reject

UNSUPPORTED_EVENT_TYPES: Final = frozenset({"stats", "engine"})
"""Suricata records that describe the sensor, not the network. Everything else that is
not a known type maps to ``EventType.other`` and keeps its payload."""

REQUIRED_FIELDS: Final = frozenset({"timestamp", "event_type"})

MAX_DETAIL_CHARS: Final = 512
MAX_DETAIL_ERRORS: Final = 5

# Column caps for the promoted text fields (docs/data-model.md: "sanitised, capped").
DNS_QUERY_CHARS: Final = 512
DNS_RRTYPE_CHARS: Final = 16
DNS_RCODE_CHARS: Final = 32
HTTP_HOST_CHARS: Final = 512
HTTP_URL_CHARS: Final = 2048
SIGNATURE_CHARS: Final = 512
CATEGORY_CHARS: Final = 256
PROTO_CHARS: Final = 32


@dataclass(frozen=True, slots=True)
class TimestampWindow:
    """How far from ``now`` an ``event_time`` may sit before it is refused (T-1.7).

    Lab and public datasets are often years old, so the past window is generous by
    default; the future window is tight because a future timestamp is almost always a
    clock fault or a forgery.
    """

    max_past: timedelta = timedelta(days=3650)
    max_future: timedelta = timedelta(hours=24)


DEFAULT_WINDOW: Final = TimestampWindow()

_EVENT_TYPES_BY_VALUE: Final = {member.value: member for member in EventType}


def map_event_type(raw: str) -> EventType:
    return _EVENT_TYPES_BY_VALUE.get(raw, EventType.other)


def _cap(value: str | None, max_chars: int) -> str | None:
    return None if value is None else clean_text(value, max_chars)


def _dns_fields(dns: DnsInfo | None) -> tuple[str | None, str | None, str | None]:
    if dns is None:
        return None, None, None
    query, rrtype = dns.rrname, dns.rrtype
    if query is None and dns.queries:
        first = dns.queries[0]
        query, rrtype = first.rrname, first.rrtype
    return (
        _cap(query, DNS_QUERY_CHARS),
        _cap(rrtype, DNS_RRTYPE_CHARS),
        _cap(dns.rcode, DNS_RCODE_CHARS),
    )


def _validation_reject(error: ValidationError, raw: str) -> Reject:
    """Reason and detail from error kinds and field paths only; input values never leak."""
    missing = sorted(
        str(item["loc"][0])
        for item in error.errors()
        if item["type"] == "missing" and item["loc"] and str(item["loc"][0]) in REQUIRED_FIELDS
    )
    if missing:
        return Reject(
            RejectReason.missing_required,
            f"missing required field(s): {', '.join(missing)}",
            excerpt(raw),
        )
    problems = [
        f"{'.'.join(str(part) for part in item['loc']) or '<root>'}: {item['type']}"
        for item in error.errors()[:MAX_DETAIL_ERRORS]
    ]
    return Reject(
        RejectReason.schema_invalid,
        clean_text("schema validation failed: " + "; ".join(problems), MAX_DETAIL_CHARS),
        excerpt(raw),
    )


def normalize_line(
    line: str,
    *,
    now: datetime,
    limits: ParseLimits = DEFAULT_LIMITS,
    window: TimestampWindow = DEFAULT_WINDOW,
) -> NormalizedEvent | Reject:
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    raw = line.rstrip("\r\n")

    if encoded_size(raw) > limits.max_line_bytes:
        return Reject(
            RejectReason.too_large, f"line exceeds {limits.max_line_bytes} bytes", excerpt(raw)
        )
    if bracket_depth(raw, stop_above=limits.max_json_depth) > limits.max_json_depth:
        return Reject(
            RejectReason.too_deep,
            f"nesting exceeds {limits.max_json_depth} levels",
            excerpt(raw),
        )
    try:
        parsed: object = json.loads(raw)
    except (ValueError, RecursionError):
        return Reject(RejectReason.json_parse, "line is not valid JSON", excerpt(raw))
    if not isinstance(parsed, dict):
        return Reject(
            RejectReason.schema_invalid, "top-level JSON value is not an object", excerpt(raw)
        )
    violation = structure_violation(parsed, limits)
    if violation is not None:
        return Reject(violation, "record breaks the structural limits", excerpt(raw))

    sanitized = clean_record(parsed, max_chars=limits.max_string_chars)
    try:
        record = EveRecord.model_validate(sanitized)
    except ValidationError as error:
        return _validation_reject(error, raw)

    if record.event_type in UNSUPPORTED_EVENT_TYPES:
        return Reject(
            RejectReason.unsupported_event_type,
            f"event_type {record.event_type!r} describes the sensor, not the network",
            excerpt(raw),
        )
    lower = now - window.max_past
    upper = now + window.max_future
    if not lower <= record.timestamp <= upper:
        return Reject(
            RejectReason.timestamp_out_of_range,
            f"timestamp {record.timestamp.isoformat()} is outside "
            f"[{lower.astimezone(UTC).isoformat()}, {upper.astimezone(UTC).isoformat()}]",
            excerpt(raw),
        )

    dns_query, dns_rrtype, dns_rcode = _dns_fields(record.dns)
    flow = record.flow
    http = record.http
    alert = record.alert
    return NormalizedEvent(
        event_hash=event_hash(hash_material(record, sanitized)),
        event_time=record.timestamp,
        event_type=map_event_type(record.event_type),
        flow_id=record.flow_id,
        src_ip=record.src_ip,
        dest_ip=record.dest_ip,
        src_port=record.src_port,
        dest_port=record.dest_port,
        proto=_cap(record.proto, PROTO_CHARS),
        app_proto=_cap(record.app_proto, PROTO_CHARS),
        bytes_toserver=None if flow is None else flow.bytes_toserver,
        bytes_toclient=None if flow is None else flow.bytes_toclient,
        pkts_toserver=None if flow is None else flow.pkts_toserver,
        pkts_toclient=None if flow is None else flow.pkts_toclient,
        dns_query=dns_query,
        dns_rrtype=dns_rrtype,
        dns_rcode=dns_rcode,
        http_host=None if http is None else _cap(http.hostname, HTTP_HOST_CHARS),
        http_url_path=None if http is None else _cap(http.url, HTTP_URL_CHARS),
        sig_signature=None if alert is None else _cap(alert.signature, SIGNATURE_CHARS),
        sig_category=None if alert is None else _cap(alert.category, CATEGORY_CHARS),
        sig_signature_id=None if alert is None else alert.signature_id,
        sig_severity=None if alert is None else alert.severity,
        payload=sanitized,
    )


def normalize_lines(
    lines: list[str] | tuple[str, ...],
    *,
    now: datetime,
    limits: ParseLimits = DEFAULT_LIMITS,
    window: TimestampWindow = DEFAULT_WINDOW,
) -> list[tuple[int, NormalizedEvent | Reject]]:
    """Convenience for tests and the sync ingest path: ``(line_number, outcome)`` pairs,
    1-based, blank lines skipped."""
    return [
        (number, normalize_line(line, now=now, limits=limits, window=window))
        for number, line in enumerate(lines, start=1)
        if line.strip()
    ]


__all__: list[str] = [
    "DEFAULT_WINDOW",
    "UNSUPPORTED_EVENT_TYPES",
    "TimestampWindow",
    "map_event_type",
    "normalize_line",
    "normalize_lines",
]
