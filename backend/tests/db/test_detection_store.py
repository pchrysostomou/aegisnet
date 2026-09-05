"""The detection tables against PostgreSQL 16: the registry, the runs, alerts with their
links, the UNIQUE dedup key, filters and cursors; then the whole sweep end to end over a
labelled fixture ingested through the real pipeline."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from aegisnet.adapters.db.asset_store import SqlAssetStore
from aegisnet.adapters.db.detection_store import SqlAlertStore, SqlDetectorRunStore, SqlRuleStore
from aegisnet.adapters.db.event_read_store import SqlEventReadStore
from aegisnet.adapters.db.ingest_store import SqlIngestStore
from aegisnet.adapters.db.session import make_session_factory
from aegisnet.domain.assets import AssetSpec
from aegisnet.domain.detectors import reproduce
from aegisnet.domain.enums import (
    AlertAssetRole,
    DetectorRunStatus,
    EntityType,
    IngestMethod,
    SampleRole,
    SourceType,
)
from aegisnet.domain.ports import AlertFilter, BatchProvenance, NewAlert
from aegisnet.services.asset_service import AssetService
from aegisnet.services.detection_service import DetectionService
from aegisnet.services.ingest_service import IngestService, limits_from_settings
from tests.conftest import REPO_ROOT, make_settings

pytestmark = [pytest.mark.db, pytest.mark.integration]

FIXTURE = (
    REPO_ROOT
    / "backend"
    / "tests"
    / "fixtures"
    / "labelled"
    / "D-001-port-scan"
    / "positive"
    / "vertical-40-ports"
    / "events.ndjson"
)
WINDOW_START = datetime(2026, 9, 1, 10, 0, tzinfo=UTC)
WINDOW_END = WINDOW_START + timedelta(minutes=10)
T0 = datetime(2026, 9, 5, 12, 0, tzinfo=UTC)
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


@pytest.fixture
def service(sessions) -> DetectionService:  # type: ignore[no-untyped-def]
    clock = iter(T0 + timedelta(seconds=i) for i in range(10_000))
    return DetectionService(
        SqlRuleStore(sessions),
        SqlDetectorRunStore(sessions),
        SqlAlertStore(sessions),
        SqlEventReadStore(sessions),
        AssetService(SqlAssetStore(sessions)),
        clock=lambda: next(clock),
    )


async def _ingest_fixture(sessions) -> None:  # type: ignore[no-untyped-def]
    ingest = IngestService(SqlIngestStore(sessions), limits_from_settings(make_settings()))
    with FIXTURE.open("rb") as handle:
        summary = await ingest.ingest(handle, PROVENANCE)
    assert summary.counts.stored == 40


async def test_rules_upsert_to_the_code_version_and_keep_the_operator_flag(sessions) -> None:  # type: ignore[no-untyped-def]
    store = SqlRuleStore(sessions)
    first = await store.upsert(
        rule_id="D-001",
        name="Port scan",
        version=1,
        base_severity=3,
        window_seconds=600,
        params={"a": 1},
        description="d",
        mitre_hint=None,
        now=T0,
    )
    same = await store.upsert(
        rule_id="D-001",
        name="Port scan",
        version=1,
        base_severity=3,
        window_seconds=600,
        params={"a": 1},
        description="d",
        mitre_hint=None,
        now=T0 + timedelta(1),
    )
    assert (
        same.id == first.id and same.updated_at == first.updated_at
    )  # nothing changed, nothing stamped
    disabled = await store.set_enabled("D-001", False, T0 + timedelta(2))
    assert disabled is not None and disabled.enabled is False
    bumped = await store.upsert(
        rule_id="D-001",
        name="Port scan",
        version=2,
        base_severity=3,
        window_seconds=600,
        params={"a": 2},
        description="d",
        mitre_hint="T1046",
        now=T0 + timedelta(3),
    )
    assert bumped.id == first.id and bumped.version == 2 and bumped.params == {"a": 2}
    assert bumped.enabled is False and bumped.updated_at == T0 + timedelta(3)
    assert await store.set_enabled("D-404", True, T0) is None
    assert [r.rule_id for r in await store.list()] == ["D-001"]


async def test_alerts_dedup_at_the_database_and_link_their_samples_and_assets(sessions) -> None:  # type: ignore[no-untyped-def]
    await _ingest_fixture(sessions)
    rules = SqlRuleStore(sessions)
    await rules.upsert(
        rule_id="D-001",
        name="Port scan",
        version=1,
        base_severity=3,
        window_seconds=600,
        params={},
        description="d",
        mitre_hint=None,
        now=T0,
    )
    assets = AssetService(SqlAssetStore(sessions))
    asset = await assets.create(
        AssetSpec.model_validate(
            {
                "hostname": "s.lab.example.test",
                "environment": "lab",
                "criticality": 5,
                "networks": [{"cidr": "10.10.0.99/32"}],
            }
        )
    )
    events, truncated = await SqlEventReadStore(sessions).load(
        WINDOW_START, WINDOW_END, max_events=1000
    )
    assert len(events) == 40 and not truncated
    assert [e.event_time for e in events] == sorted(e.event_time for e in events)
    store = SqlAlertStore(sessions)

    def alert(key: str, first: datetime) -> NewAlert:
        return NewAlert(
            rule_id="D-001",
            rule_version=1,
            dedup_key=key,
            severity=4,
            confidence=0.75,
            severity_rationale={"result": 4},
            entity_type=EntityType.src_ip,
            entity_value="10.10.0.99",
            first_seen=first,
            last_seen=first + timedelta(minutes=2),
            evidence={"flows": 40},
            event_count=40,
            samples=((events[0].id, SampleRole.first), (events[-1].id, SampleRole.last)),
            assets=((asset.id, AlertAssetRole.source),),
        )

    assert (
        await store.create_many(
            [alert("k1", WINDOW_START), alert("k2", WINDOW_START + timedelta(minutes=10))], T0
        )
        == 2
    )
    assert (
        await store.create_many(
            [alert("k1", WINDOW_START), alert("k3", WINDOW_START + timedelta(minutes=20))], T0
        )
        == 1
    )
    page = await store.list(AlertFilter(limit=2))
    assert [a.dedup_key for a in page.items] == ["k3", "k2"] and page.next_cursor
    rest = await store.list(AlertFilter(limit=2, cursor=page.next_cursor))
    assert [a.dedup_key for a in rest.items] == ["k1"] and rest.next_cursor is None
    assert [
        a.dedup_key
        for a in (
            await store.list(
                AlertFilter(
                    time_from=WINDOW_START + timedelta(minutes=10),
                    time_to=WINDOW_START + timedelta(minutes=20),
                )
            )
        ).items
    ] == ["k2"]
    assert (await store.list(AlertFilter(severity_min=5))).items == ()
    assert (await store.list(AlertFilter(entity_type=EntityType.dest_ip))).items == ()
    detail = await store.get(page.items[0].id)
    assert (
        detail is not None and detail.alert.confidence == 0.75 and detail.alert.rule_id == "D-001"
    )
    assert {role for _, role in detail.events} == {SampleRole.first, SampleRole.last}
    assert detail.assets == ((asset.id, AlertAssetRole.source),)
    assert await store.get(uuid4()) is None
    async with sessions() as session:
        links = (await session.execute(text("SELECT count(*) FROM alert_events"))).scalar_one()
    assert links == 6  # two samples for each of the three alerts, none for the refused duplicate


async def test_the_sweep_runs_end_to_end_on_postgres(sessions, service: DetectionService) -> None:  # type: ignore[no-untyped-def]
    await _ingest_fixture(sessions)
    await AssetService(SqlAssetStore(sessions)).create(
        AssetSpec.model_validate(
            {
                "hostname": "s.lab.example.test",
                "environment": "lab",
                "criticality": 5,
                "networks": [{"cidr": "10.10.0.99/32"}],
            }
        )
    )
    outcome = await service.sweep(WINDOW_START, WINDOW_START + timedelta(hours=1))
    assert outcome.events_examined == 40 and outcome.alerts_created == 1
    [run] = outcome.runs
    assert run.status is DetectorRunStatus.success and run.alerts_created == 1
    again = await service.sweep(
        WINDOW_START - timedelta(minutes=7), WINDOW_START + timedelta(minutes=13)
    )
    assert again.alerts_created == 0
    [alert] = (await service.list_alerts(AlertFilter())).items
    assert alert.severity == 4 and reproduce(alert.severity_rationale) == 4
    assert alert.dedup_key == f"D-001:src_ip=10.10.0.99:{WINDOW_START.isoformat()}"
    detail = await service.get_alert(alert.id)
    assert len(detail.events) == 20 and len(detail.assets) == 1
    runs = await service.list_runs(limit=10)
    assert [r.alerts_created for r in runs] == [0, 1] and all(r.rule_id == "D-001" for r in runs)
    assert [r.version for r in await service.list_rules()] == [1]
