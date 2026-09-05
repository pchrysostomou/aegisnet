"""D-002 auth-failure burst: the indicator match, the count, the densest-span guard."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from aegisnet.domain.detectors import (
    AuthBurstDetector,
    AuthBurstParams,
    DetectionError,
    EntityType,
    EventWindow,
)
from aegisnet.domain.detectors.auth_burst import densest_span, is_auth_failure
from aegisnet.domain.enums import EventType
from aegisnet.domain.ports import EventRow
from tests.detectors.conftest import WINDOW_END, WINDOW_START, flow_row

pytestmark = pytest.mark.unit

ATTACKER = "10.10.0.66"


def alert_row(
    when: datetime,
    src: str = ATTACKER,
    dst: str = "10.10.0.20",
    dport: int = 22,
    *,
    signature: str = "ET SCAN Potential SSH Brute Force Attempt",
    category: str = "Attempted Administrator Privilege Gain",
    sid: int = 2001219,
) -> EventRow:
    base = flow_row(when, src, dst, dport, event_type=EventType.alert, event_id=uuid4())
    return EventRow(
        **{
            **{f: getattr(base, f) for f in base.__dataclass_fields__},
            "sig_signature": signature,
            "sig_category": category,
            "sig_signature_id": sid,
            "sig_severity": 2,
        }
    )


def _window(rows: list[EventRow]) -> EventWindow:
    return EventWindow(WINDOW_START, WINDOW_END, tuple(rows))


def _burst(
    count: int, seconds: float, *, start: datetime = WINDOW_START, **kw: object
) -> list[EventRow]:
    step = seconds / max(count, 1)
    return [alert_row(start + timedelta(seconds=i * step), **kw) for i in range(count)]  # type: ignore[arg-type]


def test_indicator_matching_reads_signature_and_category_case_insensitively() -> None:
    patterns = AuthBurstParams().signature_patterns
    assert is_auth_failure(alert_row(WINDOW_START), patterns)
    assert is_auth_failure(
        alert_row(WINDOW_START, signature="x", category="attempted user PRIVILEGE GAIN"), patterns
    )
    assert not is_auth_failure(
        alert_row(WINDOW_START, signature="ET INFO STUN", category="Misc activity"), patterns
    )
    assert not is_auth_failure(flow_row(WINDOW_START, ATTACKER, "10.10.0.20", 22), patterns)
    custom = AuthBurstParams(signature_patterns=(" Kerberos Pre-Auth ",)).signature_patterns
    assert custom == ("kerberos pre-auth",)


def test_densest_span_counts_the_busiest_interval() -> None:
    times = [WINDOW_START + timedelta(seconds=s) for s in (0, 10, 20, 200, 205, 210, 215, 900)]
    assert (
        densest_span(times, 30) == 4 and densest_span(times, 5) == 2 and densest_span([], 60) == 0
    )


def test_params_are_bounded() -> None:
    for bad in (
        {"failures": 1},
        {"burst_seconds": 0},
        {"burst_seconds": 3601},
        {"signature_patterns": ()},
        {"signature_patterns": ("",)},
    ):
        with pytest.raises(DetectionError):
            AuthBurstParams(**bad)  # type: ignore[arg-type]


def test_a_burst_at_the_threshold_fires_and_one_under_does_not() -> None:
    detector = AuthBurstDetector(AuthBurstParams(failures=10, burst_seconds=120))
    assert detector.run(_window(_burst(9, 30))) == []
    [hit] = detector.run(_window(_burst(10, 30)))
    assert hit.entity.type is EntityType.src_ip and hit.entity.value == ATTACKER
    assert hit.evidence["failures"] == 10 and hit.evidence["max_burst"] == 10
    assert hit.signal_strength == pytest.approx(1 / 3, abs=1e-4) and hit.confidence == 1.0
    assert hit.evidence["sample_targets"] == ["10.10.0.20:22"] and hit.evidence[
        "signature_ids"
    ] == [2001219]


def test_a_steady_probe_reaches_the_count_but_never_the_burst() -> None:
    """The named hard negative: one failure a minute for ten minutes."""
    detector = AuthBurstDetector()
    steady = [alert_row(WINDOW_START + timedelta(seconds=5 + 60 * i)) for i in range(10)]
    assert detector.run(_window(steady)) == []
    tight = AuthBurstDetector(AuthBurstParams(failures=10, burst_seconds=600))
    [hit] = tight.run(_window(steady))
    assert hit.evidence["max_burst"] == 10


def test_targets_and_categories_are_aggregated_per_source_and_bounded() -> None:
    detector = AuthBurstDetector(AuthBurstParams(failures=10, burst_seconds=120))
    rows = _burst(12, 60, dport=22) + _burst(
        12,
        60,
        dst="10.10.0.31",
        dport=3389,
        sid=2001972,
        signature="ET SCAN RDP Brute Force Login Attempt",
        start=WINDOW_START + timedelta(seconds=3),
    )
    rows += _burst(
        40, 590, src="10.10.0.11", signature="ET INFO STUN", category="Misc activity", sid=1
    )
    [hit] = detector.run(_window(rows))
    assert hit.event_count == 24 and hit.evidence["distinct_targets"] == 2
    assert hit.evidence["sample_targets"] == ["10.10.0.20:22", "10.10.0.31:3389"]
    assert hit.evidence["signature_ids"] == [2001219, 2001972]
    assert hit.evidence["sample_categories"] == ["Attempted Administrator Privilege Gain"]
    assert 0.5 < hit.confidence <= 1.0 and len(hit.samples) == 20
    assert all(len(str(v)) <= 128 for v in hit.evidence.values() if not isinstance(v, list))


def test_the_detector_is_pure_and_sorted_by_source() -> None:
    detector = AuthBurstDetector(AuthBurstParams(failures=5, burst_seconds=60))
    rows = _burst(6, 30, src="10.10.0.9") + _burst(6, 30, src="10.10.0.2")
    first = detector.run(_window(rows))
    second = detector.run(_window(list(reversed(rows))))
    assert first == second and [r.entity.value for r in first] == ["10.10.0.2", "10.10.0.9"]
    assert datetime.now(tz=UTC) > WINDOW_START


def test_the_spec_describes_the_rule() -> None:
    spec = AuthBurstDetector().spec
    assert spec.rule_id == "D-002" and spec.base_severity == 3 and spec.window_seconds == 600
    assert spec.params["failures"] == 10 and spec.params["burst_seconds"] == 120
    assert "brute" in spec.params["signature_patterns"] and spec.mitre_hint
