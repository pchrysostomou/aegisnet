"""D-004 beaconing: regularity, the jitter bound, the outbound guard, the allow-lists."""

from __future__ import annotations

from datetime import datetime, timedelta
from uuid import uuid4

import pytest

from aegisnet.domain.detectors import (
    BeaconingDetector,
    BeaconingParams,
    DetectionError,
    EventWindow,
    is_internal,
)
from aegisnet.domain.detectors.beaconing import interval_stats
from aegisnet.domain.enums import EventType
from aegisnet.domain.ports import EventRow
from tests.detectors.conftest import WINDOW_START, flow_row

pytestmark = pytest.mark.unit

HOST = "10.10.0.41"
C2 = "198.51.100.7"
WINDOW_END = WINDOW_START + timedelta(hours=1)


def _flow(
    when: datetime,
    dst: str = C2,
    dport: int = 443,
    *,
    src: str = HOST,
    app_proto: str | None = None,
    bytes_out: int = 900,
) -> EventRow:
    base = flow_row(when, src, dst, dport, answered=True, event_id=uuid4())
    return EventRow(
        **{
            **{f: getattr(base, f) for f in base.__dataclass_fields__},
            "app_proto": app_proto,
            "bytes_toserver": bytes_out,
        }
    )


def _beacon(
    interval: float, count: int, *, jitter_pattern: tuple[float, ...] = (0.0,), **kw: object
) -> list[EventRow]:
    rows = []
    when = WINDOW_START + timedelta(seconds=5)
    for i in range(count):
        rows.append(_flow(when, **kw))  # type: ignore[arg-type]
        when += timedelta(seconds=interval * (1 + jitter_pattern[i % len(jitter_pattern)]))
    return rows


def _window(rows: list[EventRow]) -> EventWindow:
    return EventWindow(WINDOW_START, WINDOW_END, tuple(rows))


def test_helpers() -> None:
    assert interval_stats([]) == (0.0, 0.0)
    mean, stddev = interval_stats([60.0, 60.0, 60.0])
    assert mean == 60.0 and stddev == 0.0
    assert is_internal("10.0.0.1") and is_internal("192.168.1.1") and is_internal("127.0.0.1")
    assert is_internal("169.254.10.1") and is_internal("100.64.1.1") and is_internal("fe80::1")
    assert not is_internal("198.51.100.7") and not is_internal(
        "203.0.113.9"
    )  # documentation ranges count as external
    assert not is_internal("8.8.8.8")


def test_params_are_bounded_and_normalised() -> None:
    for bad in (
        {"min_connections": 2},
        {"max_jitter": 0.0},
        {"min_interval_seconds": 0},
        {"allowed_destinations": ("not-an-ip",)},
        {"allowed_ports": (70000,)},
    ):
        with pytest.raises(DetectionError):
            BeaconingParams(**bad)  # type: ignore[arg-type]
    params = BeaconingParams(
        allowed_destinations=("203.0.113.5", "198.51.100.0/24"), allowed_app_protos=(" NTP ",)
    )
    assert params.allowed_destinations == (
        "203.0.113.5/32",
        "198.51.100.0/24",
    ) and params.allowed_app_protos == ("ntp",)


def test_a_regular_beacon_fires_and_reports_its_interval() -> None:
    detector = BeaconingDetector()
    [hit] = detector.run(_window(_beacon(60, 30, jitter_pattern=(0.02, -0.02))))
    assert hit.entity.value == HOST and hit.evidence["destination"] == f"{C2}:443"
    assert hit.evidence["connections"] == 30 and 58 <= hit.evidence["mean_interval_seconds"] <= 62
    assert hit.evidence["jitter"] < 0.05 and hit.confidence > 0.9 and hit.event_count == 30
    assert hit.signal_strength == 1.0  # 30 connections, threshold 10, saturates at 3x
    assert detector.run(_window(_beacon(60, 9))) == []  # under min_connections


def test_jitter_and_short_intervals_are_guards() -> None:
    detector = BeaconingDetector()
    alternating = _beacon(300, 11, jitter_pattern=(-0.4, 0.4))  # 180 s / 420 s
    assert detector.run(_window(alternating)) == []
    rapid = _beacon(2, 40)  # a burst, not a beacon
    assert detector.run(_window(rapid)) == []


def test_internal_destinations_allowed_ports_protocols_and_networks_are_excluded() -> None:
    detector = BeaconingDetector()
    assert detector.run(_window(_beacon(30, 60, dst="10.10.0.60", dport=9100))) == []
    assert detector.run(_window(_beacon(60, 30, dst="203.0.113.123", dport=123))) == []
    assert detector.run(_window(_beacon(60, 30, app_proto="ntp"))) == []
    listed = BeaconingDetector(BeaconingParams(allowed_destinations=("198.51.100.0/24",)))
    assert listed.run(_window(_beacon(60, 30))) == []
    inclusive = BeaconingDetector(BeaconingParams(include_internal=True))
    assert len(inclusive.run(_window(_beacon(30, 60, dst="10.10.0.60", dport=9100)))) == 1


def test_the_most_regular_destination_wins_and_noise_is_ignored() -> None:
    detector = BeaconingDetector()
    rows = _beacon(45, 40, jitter_pattern=(0.05, -0.05))
    rows += _beacon(90, 15, dst="203.0.113.9", jitter_pattern=(0.0,))  # tighter, fewer
    gaps = (5, 130, 12, 200, 7, 90, 45, 300)
    when = WINDOW_START + timedelta(seconds=3)
    for i in range(40):
        if when >= WINDOW_END:
            break
        rows.append(_flow(when, dst=f"198.51.100.{100 + i % 7}"))
        when += timedelta(seconds=gaps[i % len(gaps)])
    [hit] = detector.run(_window(rows))
    assert hit.evidence["destination"] == "203.0.113.9:443"  # lowest jitter first
    assert hit.evidence["beaconing_destinations"] == ["203.0.113.9:443", f"{C2}:443"]
    assert hit.event_count == 55  # the two beacons; the irregular browsing never counts


def test_purity_and_the_spec() -> None:
    detector = BeaconingDetector()
    rows = _beacon(60, 20)
    assert detector.run(_window(rows)) == detector.run(_window(list(reversed(rows))))
    spec = detector.spec
    assert spec.rule_id == "D-004" and spec.window_seconds == 3600 and spec.base_severity == 4
    assert spec.params["min_connections"] == 10 and 123 in spec.params["allowed_ports"]
    assert any(r.event_type is EventType.flow for r in rows)
