"""The baseline job: per-asset hourly outbound history summarised into asset_baselines, and
the sweep handing those rows to the window as address-keyed baselines."""

from __future__ import annotations

from datetime import timedelta
from uuid import uuid4

import pytest

from aegisnet.domain.assets import AssetSpec
from aegisnet.domain.detectors import VolumeAnomalyDetector, summarize
from aegisnet.domain.enums import BaselineMetric
from aegisnet.domain.ports import AlertFilter
from aegisnet.services.asset_service import AssetService
from aegisnet.services.baseline_service import BaselineError, BaselineService
from aegisnet.services.detection_service import DetectionService
from tests.detectors.conftest import WINDOW_START, flow_row
from tests.detectors.test_volume_anomaly import MIB, _flow
from tests.fakes import (
    Clock,
    FakeAlertStore,
    FakeAssetStore,
    FakeBaselineStore,
    FakeDetectorRunStore,
    FakeEventStore,
    FakeRuleStore,
)

pytestmark = pytest.mark.unit

ASSET = "10.10.0.31"


def test_summarize_is_the_documented_statistic() -> None:
    assert summarize([]).sample_count == 0
    summary = summarize([10, 20, 30, 40, 100])
    assert summary.mean == 40 and summary.sample_count == 5 and summary.p95 == 100
    assert summary.stddev == pytest.approx(31.6228, abs=1e-3)
    assert summarize([5]).p95 == 5


async def test_recompute_writes_one_row_per_asset_with_history() -> None:
    clock = Clock(WINDOW_START + timedelta(days=8))
    assets, events, baselines = FakeAssetStore(), FakeEventStore(), FakeBaselineStore()
    service = AssetService(assets, clock=clock)
    asset = await service.create(
        AssetSpec.model_validate(
            {
                "hostname": "a.lab.example.test",
                "environment": "lab",
                "networks": [{"cidr": "10.10.0.31/32"}],
            }
        )
    )
    await service.create(
        AssetSpec.model_validate(
            {
                "hostname": "quiet.lab.example.test",
                "environment": "lab",
                "networks": [{"cidr": "10.10.0.32/32"}],
            }
        )
    )
    # 7 days of history: 10 MiB every hour plus one 100 MiB hour; internal traffic is ignored
    for day in range(7):
        for hour in range(24):
            when = WINDOW_START + timedelta(days=day, hours=hour, minutes=7)
            events.rows[uuid4()] = _flow(when, 10 * MIB)
            events.rows[uuid4()] = _flow(when, 5 * MIB, dst="10.10.0.20")  # internal, ignored
    events.rows[uuid4()] = _flow(WINDOW_START + timedelta(days=3, hours=2, minutes=30), 90 * MIB)
    with pytest.raises(BaselineError):
        BaselineService(assets, events, baselines, clock=clock, window_days=0)
    run = await BaselineService(assets, events, baselines, clock=clock, window_days=7).recompute(
        until=WINDOW_START + timedelta(days=7)
    )
    assert run.assets_considered == 2 and run.baselines_written == 1
    assert run.window_start == WINDOW_START and run.window_end == WINDOW_START + timedelta(days=7)
    [row] = await baselines.list()
    assert row.asset_id == asset.id and row.metric is BaselineMetric.outbound_bytes_per_hour
    assert (
        row.sample_count == 168
        and row.p95 == 10 * MIB
        and row.mean == pytest.approx((168 * 10 * MIB + 90 * MIB) / 168)
    )
    again = await BaselineService(assets, events, baselines, clock=clock).recompute(
        until=WINDOW_START + timedelta(days=7)
    )
    assert again.baselines_written == 1 and len(await baselines.list()) == 1  # upsert, not append


async def test_the_sweep_puts_the_asset_baseline_on_the_window_by_address() -> None:
    clock = Clock(WINDOW_START + timedelta(days=8))
    assets, events, baselines = FakeAssetStore(), FakeEventStore(), FakeBaselineStore()
    service = AssetService(assets, clock=clock)
    asset = await service.create(
        AssetSpec.model_validate(
            {
                "hostname": "a.lab.example.test",
                "environment": "lab",
                "criticality": 4,
                "networks": [{"cidr": "10.10.0.0/24"}],
            }
        )
    )
    await baselines.upsert(
        asset_id=asset.id,
        metric=BaselineMetric.outbound_bytes_per_hour,
        window_days=7,
        mean=20 * MIB,
        stddev=5 * MIB,
        p95=30 * MIB,
        sample_count=168,
        now=clock.now,
    )
    for i in range(40):
        events.rows[uuid4()] = _flow(WINDOW_START + timedelta(seconds=10 + i * 30), 10 * MIB)
    events.rows[uuid4()] = flow_row(
        WINDOW_START + timedelta(minutes=5), "10.10.0.99", "198.51.100.1", 443, answered=True
    )
    detection = DetectionService(
        FakeRuleStore(),
        FakeDetectorRunStore(),
        FakeAlertStore(),
        events,
        service,
        baselines=baselines,
        detectors=[VolumeAnomalyDetector()],
        clock=clock,
    )
    outcome = await detection.sweep(WINDOW_START, WINDOW_START + timedelta(hours=1))
    assert outcome.alerts_created == 1
    [alert] = (await detection.list_alerts(AlertFilter())).items
    assert (
        alert.rule_id == "D-005"
        and alert.entity_value == ASSET
        and alert.evidence["baseline_p95"] == 30 * MIB
    )
    assert alert.severity == 5  # base 3 + 0.5 (criticality 4) + 2 * 0.5 (signal 1.0) = 4.5 -> 5
    # without the baseline store the rule abstains everywhere
    blind = DetectionService(
        FakeRuleStore(),
        FakeDetectorRunStore(),
        FakeAlertStore(),
        events,
        service,
        detectors=[VolumeAnomalyDetector()],
        clock=clock,
    )
    assert (await blind.sweep(WINDOW_START, WINDOW_START + timedelta(hours=1))).alerts_created == 0
