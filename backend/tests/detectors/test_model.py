"""The bounds every detector inherits: windows, evidence, results, buckets."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from uuid import UUID, uuid4

import pytest

from aegisnet.domain.detectors import (
    MAX_EVIDENCE_CHARS,
    MAX_EVIDENCE_ITEMS,
    MAX_EVIDENCE_KEYS,
    MAX_SAMPLES,
    MAX_WINDOW,
    MAX_WINDOW_EVENTS,
    DetectionError,
    DetectionResult,
    Entity,
    EntityType,
    EventSample,
    EventWindow,
    RuleSpec,
    SampleRole,
    bounded_evidence,
    window_bucket,
)
from tests.detectors.conftest import WINDOW_END, WINDOW_START, flow_row

pytestmark = pytest.mark.unit


def test_windows_are_aware_bounded_and_sorted() -> None:
    later = flow_row(WINDOW_START + timedelta(minutes=5), "10.0.0.1", "10.0.0.2", 80)
    earlier = flow_row(WINDOW_START + timedelta(minutes=1), "10.0.0.1", "10.0.0.2", 81)
    window = EventWindow(WINDOW_START, WINDOW_END, (later, earlier))
    assert window.events == (earlier, later) and window.span == timedelta(minutes=10)
    with pytest.raises(DetectionError, match="UTC offset"):
        EventWindow(WINDOW_START.replace(tzinfo=None), WINDOW_END, ())
    with pytest.raises(DetectionError, match="after its start"):
        EventWindow(WINDOW_END, WINDOW_START, ())
    with pytest.raises(DetectionError, match="spans more"):
        EventWindow(WINDOW_START, WINDOW_START + MAX_WINDOW + timedelta(seconds=1), ())
    outside = flow_row(WINDOW_END, "10.0.0.1", "10.0.0.2", 80)
    with pytest.raises(DetectionError, match="inside the window"):
        EventWindow(WINDOW_START, WINDOW_END, (outside,))
    naive = flow_row(WINDOW_START.replace(tzinfo=None), "10.0.0.1", "10.0.0.2", 80)  # type: ignore[arg-type]
    with pytest.raises(DetectionError, match="event_time"):
        EventWindow(WINDOW_START, WINDOW_END, (naive,))


def test_the_event_cap_is_enforced() -> None:
    row = flow_row(WINDOW_START, "10.0.0.1", "10.0.0.2", 80)
    too_many = tuple(row for _ in range(MAX_WINDOW_EVENTS + 1))
    with pytest.raises(DetectionError, match="more than"):
        EventWindow(WINDOW_START, WINDOW_END, too_many)


def test_window_buckets_floor_onto_the_rule_grid() -> None:
    moment = datetime(2026, 9, 1, 10, 7, 33, tzinfo=UTC)
    assert window_bucket(moment, 600) == datetime(2026, 9, 1, 10, 0, tzinfo=UTC)
    assert window_bucket(moment, 3600) == datetime(2026, 9, 1, 10, 0, tzinfo=UTC)
    assert window_bucket(datetime(2026, 9, 1, 10, 10, tzinfo=UTC), 600) == datetime(
        2026, 9, 1, 10, 10, tzinfo=UTC
    )
    with pytest.raises(DetectionError):
        window_bucket(moment, 0)


def test_evidence_keeps_scalars_and_short_lists_only() -> None:
    cleaned = bounded_evidence(
        {
            "count": 3,
            "ratio": 0.5,
            "flag": True,
            "none": None,
            "ip": ip_address("10.0.0.1"),
            "id": UUID(int=7),
            "when": WINDOW_START,
            "ports": (80, 443),
            "hosts": {"10.0.0.2"},
        }
    )
    assert cleaned["ip"] == "10.0.0.1" and cleaned["id"] == str(UUID(int=7))
    assert cleaned["when"] == WINDOW_START.isoformat() and cleaned["ports"] == [80, 443]
    assert cleaned["hosts"] == ["10.0.0.2"] and cleaned["none"] is None
    for bad in (
        {"raw": "x"},
        {"payload": {}},
        {"line": "log text"},
        {"": 1},
        {"k" * 65: 1},
        {"text": "x" * (MAX_EVIDENCE_CHARS + 1)},
        {"text": "a\x00b"},
        {"nested": {"a": 1}},
        {"items": list(range(MAX_EVIDENCE_ITEMS + 1))},
        {"nan": float("nan")},
        {f"k{i}": i for i in range(MAX_EVIDENCE_KEYS + 1)},
    ):
        with pytest.raises(DetectionError):
            bounded_evidence(bad)


def _result(**changes: object) -> DetectionResult:
    values: dict[str, object] = {
        "rule_id": "D-001",
        "rule_version": 1,
        "entity": Entity(EntityType.src_ip, "10.0.0.1"),
        "window_bucket": WINDOW_START,
        "first_seen": WINDOW_START,
        "last_seen": WINDOW_START + timedelta(minutes=1),
        "signal_strength": 0.5,
        "confidence": 0.9,
        "event_count": 3,
        "evidence": {"flows": 3},
        "samples": (EventSample(UUID(int=1), SampleRole.first),),
    }
    values.update(changes)
    return DetectionResult(**values)  # type: ignore[arg-type]


def test_results_validate_their_fields_and_bound_their_evidence() -> None:
    result = _result(evidence={"flows": 3, "ports": [1, 2]})
    assert result.evidence == {"flows": 3, "ports": [1, 2]}
    assert result.dedup_key == f"D-001:src_ip=10.0.0.1:{WINDOW_START.isoformat()}"
    bad_cases: list[dict[str, object]] = [
        {"rule_id": "X-1"},
        {"rule_version": 0},
        {"signal_strength": 1.5},
        {"confidence": -0.1},
        {"event_count": 0},
        {"first_seen": WINDOW_START + timedelta(hours=1)},
        {"evidence": {"raw": "..."}},
        {
            "samples": tuple(
                EventSample(uuid4(), SampleRole.sample) for _ in range(MAX_SAMPLES + 1)
            ),
            "event_count": 100,
        },
        {
            "samples": (
                EventSample(UUID(int=1), SampleRole.first),
                EventSample(UUID(int=1), SampleRole.last),
            )
        },
        {
            "samples": tuple(EventSample(uuid4(), SampleRole.sample) for _ in range(4)),
            "event_count": 3,
        },
    ]
    for changes in bad_cases:
        with pytest.raises(DetectionError):
            _result(**changes)


def test_entities_and_specs_are_validated() -> None:
    with pytest.raises(DetectionError):
        Entity(EntityType.domain, "")
    with pytest.raises(DetectionError):
        Entity(EntityType.domain, " padded ")
    with pytest.raises(DetectionError):
        Entity(EntityType.domain, "a\x1bb")
    with pytest.raises(DetectionError):
        RuleSpec("D-1", "x", 1, 3, 600, {}, "d")
    with pytest.raises(DetectionError):
        RuleSpec("D-001", "x", 1, 6, 600, {}, "d")
    with pytest.raises(DetectionError):
        RuleSpec("D-001", "x", 1, 3, 0, {}, "d")
