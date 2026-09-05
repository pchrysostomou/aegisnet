"""The sweep: rules synced, windows sliced on the rule grid, severity from the inventory,
dedup on re-sweep, per-rule failure isolation, bounded intervals."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import pytest

from aegisnet.domain.assets import AssetSpec
from aegisnet.domain.detectors import (
    DetectionResult,
    EventWindow,
    PortScanDetector,
    RuleSpec,
    reproduce,
)
from aegisnet.domain.enums import AlertAssetRole, DetectorRunStatus, EntityType, SampleRole
from aegisnet.domain.ports import AlertFilter
from aegisnet.services.asset_service import AssetService
from aegisnet.services.detection_service import (
    AlertNotFoundError,
    DetectionService,
    SweepError,
    describe,
)
from tests.detectors.conftest import WINDOW_START, flow_row
from tests.fakes import (
    Clock,
    FakeAlertStore,
    FakeAssetStore,
    FakeDetectorRunStore,
    FakeEventStore,
    FakeRuleStore,
)

pytestmark = pytest.mark.unit

SCANNER = "10.10.0.99"
SWEEP_START = WINDOW_START
SWEEP_END = WINDOW_START + timedelta(minutes=20)


class BrokenDetector:
    """A rule that raises: the sweep must record it and carry on."""

    @property
    def spec(self) -> RuleSpec:
        return RuleSpec("D-999", "Broken", 1, 2, 600, {}, "always raises")

    def run(self, window: EventWindow) -> list[DetectionResult]:
        raise RuntimeError("boom \x00 with control chars")


class Harness:
    def __init__(self, detectors: list[Any] | None = None, max_events: int = 200_000) -> None:
        self.clock = Clock()
        self.rules = FakeRuleStore()
        self.runs = FakeDetectorRunStore()
        self.alerts = FakeAlertStore()
        self.events = FakeEventStore()
        self.asset_store = FakeAssetStore()
        self.assets = AssetService(self.asset_store, clock=self.clock)
        self.service = DetectionService(
            self.rules,
            self.runs,
            self.alerts,
            self.events,
            self.assets,
            detectors=detectors,
            clock=self.clock,
            max_events=max_events,
        )

    def scan(self, ports: int = 40, *, start: datetime = WINDOW_START) -> None:
        for offset in range(ports):
            row = flow_row(start + timedelta(seconds=offset), SCANNER, "10.10.0.20", offset + 1)
            self.events.rows[row.id] = row

    async def asset(self, cidr: str, criticality: int) -> None:
        await self.assets.create(
            AssetSpec.model_validate(
                {
                    "hostname": f"h{criticality}.lab.example.test",
                    "environment": "lab",
                    "criticality": criticality,
                    "networks": [{"cidr": cidr}],
                }
            )
        )


@pytest.fixture
def h() -> Harness:
    return Harness()


async def test_a_sweep_syncs_the_registry_and_writes_an_alert_with_its_links(h: Harness) -> None:
    h.scan(40)
    await h.asset("10.10.0.99/32", criticality=5)
    outcome = await h.service.sweep(SWEEP_START, SWEEP_END)
    assert outcome.events_examined == 40 and outcome.alerts_created == 1 and not outcome.truncated
    [run] = outcome.runs
    assert run.rule_id == "D-001" and run.status is DetectorRunStatus.success
    assert run.events_examined == 40 and run.alerts_created == 1 and run.error_detail is None
    assert [r.rule_id for r in await h.service.list_rules()] == ["D-001"]
    [alert] = h.alerts.rows.values()
    assert alert.entity_type is EntityType.src_ip and alert.entity_value == SCANNER
    assert alert.rule_version == 1 and alert.event_count == 40
    # base 3, criticality 5, signal 40/20/3 = 0.667 -> 3 + 1 + 0.333 -> 4
    assert alert.severity == 4 and reproduce(alert.severity_rationale) == 4
    assert alert.severity_rationale["asset_criticality_source"] == "asset"
    assert alert.dedup_key == f"D-001:src_ip={SCANNER}:{WINDOW_START.isoformat()}"
    events, assets = h.alerts.links[alert.id]
    assert len(events) == 20 and events[0][1] is SampleRole.first
    [(asset_id, role)] = assets
    assert role is AlertAssetRole.source
    assert (await h.assets.get(asset_id)).criticality == 5
    assert "payload" not in alert.evidence and alert.evidence["distinct_dest_ports"] == 40


async def test_an_unknown_source_gets_the_default_criticality_and_no_asset_link(h: Harness) -> None:
    h.scan(40)
    outcome = await h.service.sweep(SWEEP_START, SWEEP_END)
    assert outcome.alerts_created == 1
    [alert] = h.alerts.rows.values()
    assert alert.severity == 3 and alert.severity_rationale["asset_criticality_source"] == "default"
    assert h.alerts.links[alert.id][1] == ()


async def test_re_sweeping_creates_nothing_even_from_an_unaligned_interval(h: Harness) -> None:
    h.scan(40)
    first = await h.service.sweep(SWEEP_START, SWEEP_END)
    again = await h.service.sweep(
        SWEEP_START + timedelta(minutes=3), SWEEP_END - timedelta(minutes=3)
    )
    assert first.alerts_created == 1 and again.alerts_created == 0
    assert len(h.alerts.rows) == 1
    assert [r.alerts_created for r in await h.service.list_runs(limit=10)] == [0, 1]


async def test_a_disabled_rule_is_skipped_and_recorded(h: Harness) -> None:
    h.scan(40)
    await h.service.sync_rules()
    h.rules.set_enabled("D-001", False)
    outcome = await h.service.sweep(SWEEP_START, SWEEP_END)
    [run] = outcome.runs
    assert run.status is DetectorRunStatus.skipped and run.error_detail == "rule disabled"
    assert outcome.alerts_created == 0 and h.alerts.rows == {}
    assert (await h.service.list_rules())[0].enabled is False  # sync never re-enables


async def test_an_interval_over_the_event_cap_skips_every_rule() -> None:
    h = Harness(max_events=10)
    h.scan(40)
    outcome = await h.service.sweep(SWEEP_START, SWEEP_END)
    assert outcome.truncated and outcome.events_examined == 10
    [run] = outcome.runs
    assert run.status is DetectorRunStatus.skipped and "narrow the interval" in (
        run.error_detail or ""
    )


async def test_one_rule_raising_never_stops_the_others() -> None:
    h = Harness(detectors=[BrokenDetector(), PortScanDetector()])
    h.scan(40)
    outcome = await h.service.sweep(SWEEP_START, SWEEP_END)
    broken, scan = outcome.runs
    assert broken.rule_id == "D-999" and broken.status is DetectorRunStatus.error
    assert broken.error_detail is not None and broken.error_detail.startswith("RuntimeError: boom")
    assert "\x00" not in broken.error_detail
    assert scan.status is DetectorRunStatus.success and scan.alerts_created == 1
    assert outcome.alerts_created == 1


async def test_rules_are_upserted_to_the_code_version(h: Harness) -> None:
    first = await h.service.sync_rules()
    assert first["D-001"].version == 1 and first["D-001"].params["distinct_ports"] == 20

    class NewerScan(PortScanDetector):
        version = 2

    newer = DetectionService(h.rules, h.runs, h.alerts, h.events, h.assets, detectors=[NewerScan()])
    second = await newer.sync_rules()
    assert second["D-001"].version == 2 and second["D-001"].id == first["D-001"].id


@pytest.mark.parametrize(
    ("start", "end", "message"),
    [
        (WINDOW_START.replace(tzinfo=None), SWEEP_END, "UTC offset"),
        (SWEEP_END, SWEEP_START, "after its start"),
        (WINDOW_START, WINDOW_START + timedelta(hours=24, seconds=1), "at most"),
    ],
)
async def test_intervals_are_validated(
    h: Harness, start: datetime, end: datetime, message: str
) -> None:
    with pytest.raises(SweepError, match=message):
        await h.service.sweep(start, end)
    assert h.runs.rows == []


async def test_reads_validate_their_inputs(h: Harness) -> None:
    with pytest.raises(ValueError, match="limit"):
        await h.service.list_alerts(AlertFilter(limit=0))
    with pytest.raises(ValueError):
        await h.service.list_alerts(AlertFilter(cursor="nope"))
    with pytest.raises(SweepError, match="after from"):
        await h.service.list_alerts(AlertFilter(time_from=SWEEP_END, time_to=SWEEP_START))
    with pytest.raises(AlertNotFoundError):
        await h.service.get_alert(uuid4())
    with pytest.raises(SweepError, match="limit"):
        await h.service.list_runs(limit=0)


async def test_alert_reads_and_the_sweep_description(h: Harness) -> None:
    h.scan(40)
    outcome = await h.service.sweep(SWEEP_START, SWEEP_END)
    page = await h.service.list_alerts(AlertFilter(severity_min=3, rule_id="D-001"))
    [alert] = page.items
    detail = await h.service.get_alert(alert.id)
    assert detail.alert == alert and len(detail.events) == 20
    assert (await h.service.list_alerts(AlertFilter(severity_min=5))).items == ()
    description = describe(outcome)
    assert description["alerts_created"] == 1 and description["runs"][0]["rule_id"] == "D-001"
    assert description["window_start"] == SWEEP_START and description["truncated"] is False
    assert datetime.now(tz=UTC) > SWEEP_START
