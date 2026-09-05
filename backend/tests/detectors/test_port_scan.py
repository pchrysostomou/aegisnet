"""D-001 port scan: thresholds, the connection-count guard, samples, purity."""

from __future__ import annotations

import random
from datetime import timedelta

import pytest

from aegisnet.domain.detectors import (
    DetectionError,
    EntityType,
    EventWindow,
    PortScanDetector,
    PortScanParams,
    SampleRole,
)
from aegisnet.domain.enums import EventType
from aegisnet.domain.ports import EventRow
from tests.detectors.conftest import WINDOW_END, WINDOW_START, flow_row

pytestmark = pytest.mark.unit

SCANNER = "10.10.0.99"


def _rows(
    targets: list[tuple[str, int]], *, src: str = SCANNER, answered: bool = False
) -> list[EventRow]:
    return [
        flow_row(WINDOW_START + timedelta(seconds=i), src, host, port, answered=answered)
        for i, (host, port) in enumerate(targets)
    ]


def _window(rows: list[EventRow]) -> EventWindow:
    return EventWindow(WINDOW_START, WINDOW_END, tuple(rows))


def test_params_are_bounded() -> None:
    PortScanParams(distinct_ports=2, distinct_hosts=2, min_flows=2)
    for bad in ({"distinct_ports": 1}, {"distinct_hosts": 100_001}, {"min_flows": 0}):
        with pytest.raises(DetectionError):
            PortScanParams(**bad)  # type: ignore[arg-type]


def test_vertical_and_horizontal_thresholds_are_inclusive() -> None:
    detector = PortScanDetector(PortScanParams(distinct_ports=20, distinct_hosts=15, min_flows=5))
    just_under = _rows([("10.10.0.20", p) for p in range(1, 20)])
    assert detector.run(_window(just_under)) == []
    vertical = _rows([("10.10.0.20", p) for p in range(1, 21)])
    [hit] = detector.run(_window(vertical))
    assert hit.entity.type is EntityType.src_ip and hit.entity.value == SCANNER
    assert hit.evidence["distinct_dest_ports"] == 20 and hit.evidence["distinct_dest_hosts"] == 1
    horizontal_under = _rows([(f"10.10.0.{h}", 445) for h in range(101, 115)])
    assert detector.run(_window(horizontal_under)) == []
    horizontal = _rows([(f"10.10.0.{h}", 445) for h in range(101, 116)])
    [hit] = detector.run(_window(horizontal))
    assert hit.evidence["distinct_dest_hosts"] == 15 and hit.evidence["distinct_targets"] == 15


def test_many_connections_to_one_target_never_count() -> None:
    """The named hard negative: a backup client, 500 flows, one (host, port)."""
    detector = PortScanDetector()
    busy = _rows([("10.10.0.20", 22)] * 500, src="10.10.0.31", answered=True)
    assert detector.run(_window(busy)) == []


def test_min_flows_and_non_flow_events_are_respected() -> None:
    detector = PortScanDetector(PortScanParams(distinct_ports=5, distinct_hosts=5, min_flows=20))
    few = _rows([("10.10.0.20", p) for p in range(1, 11)])  # 10 distinct ports, 10 flows
    assert detector.run(_window(few)) == []
    alerts = [
        flow_row(WINDOW_START, SCANNER, "10.10.0.20", p, event_type=EventType.alert)
        for p in range(1, 41)
    ]
    assert detector.run(_window(alerts)) == []


def test_signal_confidence_samples_and_evidence_shape() -> None:
    detector = PortScanDetector(PortScanParams(distinct_ports=10, distinct_hosts=10, min_flows=10))
    unanswered = _rows([("10.10.0.20", p) for p in range(1, 31)])  # 3x the threshold
    answered = _rows([("10.10.0.21", p) for p in range(1, 11)], src="10.10.0.5", answered=True)
    results = detector.run(_window(unanswered + answered))
    assert [r.entity.value for r in results] == ["10.10.0.5", SCANNER]  # sorted by source
    scan = results[1]
    assert scan.signal_strength == 1.0 and scan.confidence == 1.0
    probe = results[0]
    assert probe.signal_strength == pytest.approx(1 / 3, abs=1e-4) and probe.confidence == 0.5
    assert scan.event_count == 30 and len(scan.samples) == 20
    roles = [s.role for s in scan.samples]
    assert roles[0] is SampleRole.first and roles[1] is SampleRole.last
    assert set(roles[2:]) == {SampleRole.sample}
    assert scan.first_seen == WINDOW_START and scan.last_seen == WINDOW_START + timedelta(
        seconds=29
    )
    assert scan.dedup_key == f"D-001:src_ip={SCANNER}:{WINDOW_START.isoformat()}"
    assert scan.evidence["sample_dest_ports"] == list(range(1, 21))
    assert scan.evidence["threshold_ports"] == 10 and scan.evidence["unanswered_flows"] == 30
    assert "payload" not in scan.evidence and all(
        not isinstance(v, str) or len(v) <= 128 for v in scan.evidence.values()
    )


def test_the_detector_is_pure_and_order_independent() -> None:
    detector = PortScanDetector()
    rows = _rows([(f"10.10.0.{h}", p) for h in range(101, 121) for p in (22, 3389)])
    shuffled = list(rows)
    random.Random(1).shuffle(shuffled)
    first = detector.run(_window(rows))
    second = detector.run(_window(shuffled))
    assert first == second and len(first) == 1
    assert detector.run(_window(rows)) == first  # no state between runs


def test_the_spec_describes_the_rule() -> None:
    spec = PortScanDetector().spec
    assert spec.rule_id == "D-001" and spec.version == 1 and spec.base_severity == 3
    assert spec.window_seconds == 600
    assert spec.params == {"distinct_ports": 20, "distinct_hosts": 15, "min_flows": 20}
    assert "distinct (host, port)" in spec.description and spec.mitre_hint
