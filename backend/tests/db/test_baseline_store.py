"""asset_baselines against PostgreSQL: the upsert, the hourly outbound aggregation the job
reads, the job end to end, and D-005 firing through the sweep once a baseline exists."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from ipaddress import ip_network

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from aegisnet.adapters.db.asset_store import SqlAssetStore
from aegisnet.adapters.db.detection_store import (
    SqlAlertStore,
    SqlBaselineStore,
    SqlDetectorRunStore,
    SqlRuleStore,
)
from aegisnet.adapters.db.event_read_store import SqlEventReadStore
from aegisnet.adapters.db.ingest_store import SqlIngestStore
from aegisnet.adapters.db.session import make_session_factory
from aegisnet.domain.assets import AssetSpec
from aegisnet.domain.enums import BaselineMetric, IngestMethod, SourceType
from aegisnet.domain.ports import AlertFilter, BatchProvenance
from aegisnet.services.asset_service import AssetService
from aegisnet.services.baseline_service import BaselineService
from aegisnet.services.detection_service import DetectionService
from aegisnet.services.ingest_service import IngestService, limits_from_settings
from tests.conftest import REPO_ROOT, make_settings

pytestmark = [pytest.mark.db, pytest.mark.integration]

LABELLED = REPO_ROOT / "backend" / "tests" / "fixtures" / "labelled"
EXFIL = LABELLED / "D-005-volume-anomaly" / "positive" / "exfil-10x-baseline" / "events.ndjson"
BACKUP = (
    LABELLED
    / "D-005-volume-anomaly"
    / "negative"
    / "nightly-backup-within-baseline"
    / "events.ndjson"
)
WINDOW_START = datetime(2026, 9, 1, 10, 0, tzinfo=UTC)
T0 = datetime(2026, 9, 5, 12, 0, tzinfo=UTC)
MIB = 1024 * 1024
PROVENANCE = BatchProvenance(
    source_type=SourceType.suricata_eve,
    source_label="fixture",
    ingest_method=IngestMethod.api_ndjson,
)


@pytest.fixture(autouse=True)
async def clean_tables(migrator_engine: AsyncEngine) -> AsyncIterator[None]:
    async with migrator_engine.begin() as connection:
        for table in (
            "alert_events",
            "alert_assets",
            "alerts",
            "detector_runs",
            "detection_rules",
            "asset_baselines",
            "ingest_rejects",
            "events",
            "ingest_batches",
            "asset_networks",
            "assets",
        ):
            await connection.execute(text(f"DELETE FROM {table}"))  # noqa: S608 - fixed names
    yield


@pytest.fixture
def sessions(app_engine: AsyncEngine):  # type: ignore[no-untyped-def]
    return make_session_factory(app_engine)


async def _ingest(sessions, path) -> int:  # type: ignore[no-untyped-def]
    ingest = IngestService(SqlIngestStore(sessions), limits_from_settings(make_settings()))
    with path.open("rb") as handle:
        return (await ingest.ingest(handle, PROVENANCE)).counts.stored


async def test_upsert_replaces_by_asset_metric_and_window(sessions) -> None:  # type: ignore[no-untyped-def]
    asset = await AssetService(SqlAssetStore(sessions)).create(
        AssetSpec.model_validate(
            {
                "hostname": "a.lab.example.test",
                "environment": "lab",
                "networks": [{"cidr": "10.10.0.31/32"}],
            }
        )
    )
    store = SqlBaselineStore(sessions)
    kw = {"asset_id": asset.id, "metric": BaselineMetric.outbound_bytes_per_hour, "window_days": 7}
    first = await store.upsert(**kw, mean=1.0, stddev=0.5, p95=2.0, sample_count=10, now=T0)
    second = await store.upsert(
        **kw, mean=3.0, stddev=1.0, p95=4.0, sample_count=20, now=T0 + timedelta(1)
    )
    assert second.id == first.id and second.mean == 3.0 and second.sample_count == 20
    other = await store.upsert(
        **{**kw, "window_days": 30}, mean=9.0, stddev=1.0, p95=9.0, sample_count=5, now=T0
    )
    assert other.id != first.id
    rows = await store.list()
    assert [(r.window_days, r.mean) for r in rows] == [(7, 3.0), (30, 9.0)]
    assert len(await store.list(metric=BaselineMetric.dns_queries_per_hour)) == 0


async def test_hourly_outbound_bytes_groups_external_traffic_per_hour(sessions) -> None:  # type: ignore[no-untyped-def]
    assert await _ingest(sessions, EXFIL) == 40
    assert await _ingest(sessions, BACKUP) == 30  # same hour, same asset, adds 650 MiB
    store = SqlEventReadStore(sessions)
    rows = await store.hourly_outbound_bytes(
        [ip_network("10.10.0.31/32")],
        WINDOW_START - timedelta(days=1),
        WINDOW_START + timedelta(days=1),
    )
    [(moment, total)] = rows
    assert moment == WINDOW_START and 1049 <= total // MIB <= 1050  # per-flow integer division
    assert (
        await store.hourly_outbound_bytes(
            [ip_network("10.10.0.99/32")], WINDOW_START, WINDOW_START + timedelta(hours=1)
        )
        == ()
    )
    assert (
        await store.hourly_outbound_bytes([], WINDOW_START, WINDOW_START + timedelta(hours=1)) == ()
    )


async def test_the_job_and_the_sweep_run_end_to_end_on_postgres(sessions) -> None:  # type: ignore[no-untyped-def]
    assert await _ingest(sessions, EXFIL) == 40
    assets = AssetService(SqlAssetStore(sessions))
    asset = await assets.create(
        AssetSpec.model_validate(
            {
                "hostname": "a.lab.example.test",
                "environment": "lab",
                "criticality": 4,
                "networks": [{"cidr": "10.10.0.31/32"}],
            }
        )
    )
    events, baselines = SqlEventReadStore(sessions), SqlBaselineStore(sessions)
    job = BaselineService(
        SqlAssetStore(sessions), events, baselines, clock=lambda: T0, window_days=7
    )
    run = await job.recompute(until=WINDOW_START + timedelta(hours=2))
    assert run.assets_considered == 1 and run.baselines_written == 1
    [row] = await baselines.list()
    assert (
        row.asset_id == asset.id and row.sample_count == 1 and row.p95 == pytest.approx(400 * MIB)
    )
    # one sampled hour is below min_samples, so D-005 abstains against the job's own row ...
    clock = iter(T0 + timedelta(seconds=i) for i in range(10_000))
    detection = DetectionService(
        SqlRuleStore(sessions),
        SqlDetectorRunStore(sessions),
        SqlAlertStore(sessions),
        events,
        assets,
        baselines=baselines,
        clock=lambda: next(clock),
    )
    first = await detection.sweep(WINDOW_START, WINDOW_START + timedelta(hours=1))
    assert [r.alerts_created for r in first.runs if r.rule_id == "D-005"] == [0]
    assert (await detection.list_alerts(AlertFilter(rule_id="D-005"))).items == ()
    # ... and fires once a mature baseline says 400 MiB is far above normal
    await baselines.upsert(
        asset_id=asset.id,
        metric=BaselineMetric.outbound_bytes_per_hour,
        window_days=7,
        mean=20 * MIB,
        stddev=5 * MIB,
        p95=30 * MIB,
        sample_count=168,
        now=T0,
    )
    outcome = await detection.sweep(WINDOW_START, WINDOW_START + timedelta(hours=1))
    assert [r.alerts_created for r in outcome.runs if r.rule_id == "D-005"] == [1]
    [alert] = (await detection.list_alerts(AlertFilter(rule_id="D-005"))).items
    assert (
        alert.entity_value == "10.10.0.31"
        and alert.severity == 5
        and alert.evidence["baseline_samples"] == 168
    )
    detail = await detection.get_alert(alert.id)
    assert [role for _, role in detail.assets] == [detail.assets[0][1]] and len(detail.events) >= 3
