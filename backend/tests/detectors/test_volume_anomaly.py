"""D-005 outbound volume anomaly: the baseline threshold, abstention, inbound is not outbound."""

from __future__ import annotations

from datetime import datetime, timedelta
from uuid import uuid4

import pytest

from aegisnet.domain.detectors import (
    Baseline,
    DetectionError,
    EventWindow,
    SampleRole,
    VolumeAnomalyDetector,
    VolumeAnomalyParams,
)
from aegisnet.domain.ports import EventRow
from tests.detectors.conftest import WINDOW_START, flow_row

pytestmark = pytest.mark.unit

MIB = 1024 * 1024
ASSET = "10.10.0.31"
WINDOW_END = WINDOW_START + timedelta(hours=1)


def _flow(
    when: datetime,
    bytes_out: int,
    *,
    dst: str = "198.51.100.9",
    bytes_in: int = 4000,
    src: str = ASSET,
) -> EventRow:
    base = flow_row(when, src, dst, 443, answered=True, event_id=uuid4())
    return EventRow(
        **{
            **{f: getattr(base, f) for f in base.__dataclass_fields__},
            "bytes_toserver": bytes_out,
            "bytes_toclient": bytes_in,
        }
    )


def _rows(total_mib: float, flows: int, **kw: object) -> list[EventRow]:
    per = int(total_mib * MIB / flows)
    return [_flow(WINDOW_START + timedelta(seconds=10 + i * 30), per, **kw) for i in range(flows)]  # type: ignore[arg-type]


def _baseline(mean_mib: float, stddev_mib: float, p95_mib: float, samples: int = 168) -> Baseline:
    return Baseline(
        "outbound_bytes_per_hour", 7, mean_mib * MIB, stddev_mib * MIB, p95_mib * MIB, samples
    )


def _window(rows: list[EventRow], baselines: dict[str, Baseline] | None = None) -> EventWindow:
    return EventWindow(WINDOW_START, WINDOW_END, tuple(rows), baselines=baselines or {})


def test_baselines_and_params_are_validated() -> None:
    with pytest.raises(DetectionError):
        Baseline("outbound_bytes_per_hour", 0, 1.0, 1.0, 1.0, 1)
    with pytest.raises(DetectionError):
        Baseline("outbound_bytes_per_hour", 7, -1.0, 1.0, 1.0, 1)
    with pytest.raises(DetectionError, match="IP address"):
        EventWindow(WINDOW_START, WINDOW_END, (), baselines={"not-an-ip": _baseline(1, 1, 1)})
    for bad in (
        {"stddev_multiplier": 0},
        {"p95_multiplier": 0.5},
        {"min_bytes": 0},
        {"min_samples": 200, "full_confidence_samples": 100},
    ):
        with pytest.raises(DetectionError):
            VolumeAnomalyParams(**bad)  # type: ignore[arg-type]


def test_the_threshold_is_the_largest_of_three_bounds() -> None:
    detector = VolumeAnomalyDetector()
    assert detector.threshold(_baseline(20, 5, 30)) == 60 * MIB  # 2 x p95 wins
    assert detector.threshold(_baseline(1, 0.5, 2)) == 50 * MIB  # the absolute floor wins
    assert (
        detector.threshold(_baseline(100, 40, 150)) == 300 * MIB
    )  # 2 x p95 = 300 > mean + 3 sd = 220


def test_an_asset_far_above_its_baseline_fires_with_a_reproducible_ratio() -> None:
    detector = VolumeAnomalyDetector()
    rows = [*_rows(390, 39), _flow(WINDOW_START + timedelta(minutes=5, seconds=5), 10 * MIB + 1)]
    [hit] = detector.run(_window(rows, {ASSET: _baseline(20, 5, 30)}))
    assert hit.entity.value == ASSET and hit.evidence["threshold_bytes"] == 60 * MIB
    assert hit.evidence["bytes_out"] == 400 * MIB + 1 and hit.evidence["ratio"] == pytest.approx(
        6.667, abs=1e-3
    )
    assert hit.signal_strength == 1.0 and hit.confidence == 1.0 and hit.event_count == 40
    assert hit.evidence["baseline_samples"] == 168 and hit.evidence["sample_destinations"] == [
        "198.51.100.9"
    ]
    assert SampleRole.peak in {s.role for s in hit.samples}
    assert detector.run(_window(_rows(59, 10), {ASSET: _baseline(20, 5, 30)})) == []  # just under


def test_the_rule_abstains_without_a_usable_baseline() -> None:
    detector = VolumeAnomalyDetector()
    assert detector.run(_window(_rows(300, 30))) == []  # no baselines on the window at all
    assert (
        detector.run(_window(_rows(300, 30), {"10.10.0.99": _baseline(1, 1, 1)})) == []
    )  # another address
    assert detector.run(_window(_rows(300, 30), {ASSET: _baseline(1, 0.5, 2, samples=5)})) == []
    assert (
        detector.run(
            _window(_rows(300, 30), {ASSET: Baseline("dns_queries_per_hour", 7, 1, 1, 1, 168)})
        )
        == []
    )


def test_only_outbound_bytes_to_external_destinations_count() -> None:
    detector = VolumeAnomalyDetector()
    inbound = [
        _flow(WINDOW_START + timedelta(seconds=10 + i * 30), 20_000, bytes_in=20 * MIB)
        for i in range(25)
    ]
    assert detector.run(_window(inbound, {ASSET: _baseline(5, 1, 8)})) == []
    internal = _rows(400, 40, dst="10.10.0.20")
    assert detector.run(_window(internal, {ASSET: _baseline(20, 5, 30)})) == []


def test_confidence_grows_with_the_baseline_sample_count_and_the_spec() -> None:
    detector = VolumeAnomalyDetector()
    [young] = detector.run(_window(_rows(400, 40), {ASSET: _baseline(20, 5, 30, samples=48)}))
    [mature] = detector.run(_window(_rows(400, 40), {ASSET: _baseline(20, 5, 30, samples=168)}))
    assert (
        young.confidence == pytest.approx(0.5 + 0.5 * 48 / 168, abs=1e-4)
        and mature.confidence == 1.0
    )
    spec = detector.spec
    assert (
        spec.rule_id == "D-005" and spec.window_seconds == 3600 and spec.params["min_samples"] == 24
    )
