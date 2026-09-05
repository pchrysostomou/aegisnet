"""The SQL event read store and batch listing against PostgreSQL 16."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address, ip_network
from uuid import uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from aegisnet.adapters.db.asset_store import SqlAssetStore
from aegisnet.adapters.db.event_read_store import SqlEventReadStore
from aegisnet.adapters.db.ingest_store import SqlIngestStore
from aegisnet.adapters.db.session import make_session_factory
from aegisnet.domain.assets import AssetSpec
from aegisnet.domain.enums import EventType, IngestMethod, IngestStatus, RejectReason, SourceType
from aegisnet.domain.ports import BatchFilter, BatchProvenance, EventQuery
from aegisnet.services.asset_service import AssetService
from aegisnet.services.event_read_service import EventReadService
from aegisnet.services.ingest_service import IngestService, limits_from_settings
from tests.conftest import REPO_ROOT

pytestmark = [pytest.mark.db, pytest.mark.integration]

FIXTURES = REPO_ROOT / "backend" / "tests" / "fixtures" / "eve"
NOW = datetime(2026, 9, 5, 12, 0, tzinfo=UTC)
WINDOW = (datetime(2026, 9, 1, tzinfo=UTC), datetime(2026, 9, 2, tzinfo=UTC))
PROVENANCE = BatchProvenance(
    source_type=SourceType.suricata_eve,
    source_label="read-suite",
    ingest_method=IngestMethod.api_ndjson,
)


@pytest.fixture(autouse=True)
async def clean_tables(migrator_engine: AsyncEngine) -> AsyncIterator[None]:
    async with migrator_engine.begin() as connection:
        for table in ("ingest_rejects", "events", "ingest_batches", "asset_networks", "assets"):
            await connection.execute(text(f"DELETE FROM {table}"))  # noqa: S608 - literal names
    yield


@pytest.fixture
async def loaded(app_engine: AsyncEngine, db_settings: object) -> tuple[IngestService, list[str]]:
    """Benign and hostile fixtures ingested as two batches."""
    sessions = make_session_factory(app_engine)
    ticks = iter(NOW + timedelta(seconds=i) for i in range(1000))  # distinct started_at per batch
    ingest = IngestService(
        SqlIngestStore(sessions),
        limits_from_settings(db_settings),  # type: ignore[arg-type]
        clock=lambda: next(ticks),
    )
    benign = (FIXTURES / "benign.ndjson").read_text(encoding="utf-8").splitlines()
    hostile = (FIXTURES / "hostile.ndjson").read_text(encoding="utf-8").splitlines()
    await ingest.ingest(benign, PROVENANCE)
    await ingest.ingest(
        hostile, BatchProvenance(SourceType.suricata_eve, "hostile", IngestMethod.api_ndjson)
    )
    return ingest, benign


@pytest.fixture
def events(app_engine: AsyncEngine) -> EventReadService:
    return EventReadService(SqlEventReadStore(make_session_factory(app_engine)))


def _query(**overrides: object) -> EventQuery:
    base: dict[str, object] = {"time_from": WINDOW[0], "time_to": WINDOW[1]}
    return EventQuery(**{**base, **overrides})  # type: ignore[arg-type]


async def test_window_and_type_filters(loaded: object, events: EventReadService) -> None:
    page = await events.query(_query(limit=200))
    assert len(page.items) == 13 and page.next_cursor is None  # 11 benign + 2 hostile-but-valid
    assert [row.event_time for row in page.items] == sorted(
        (row.event_time for row in page.items), reverse=True
    )
    dns = await events.query(_query(event_types=(EventType.dns,)))
    assert {row.event_type for row in dns.items} == {EventType.dns} and len(dns.items) == 4
    assert all(row.payload is None for row in dns.items)
    outside = await events.query(_query(time_from=WINDOW[1], time_to=WINDOW[1] + timedelta(days=1)))
    assert outside.items == ()


async def test_address_port_flow_and_batch_filters(
    loaded: tuple[IngestService, list[str]], events: EventReadService
) -> None:
    ingest, _ = loaded
    by_cidr = await events.query(_query(src_ip=ip_network("10.10.0.0/24"), dest_ports=(53,)))
    assert {row.dest_port for row in by_cidr.items} == {53}
    assert all(row.src_ip in ip_network("10.10.0.0/24") for row in by_cidr.items)  # type: ignore[operator]
    exact = await events.query(
        _query(dest_ip=ip_address("203.0.113.10"), event_types=(EventType.alert,))
    )
    assert len(exact.items) == 1 and exact.items[0].sig_signature_id == 9000001
    flow = await events.query(_query(flow_id=2222222222222222))
    assert len(flow.items) == 2
    batches = await ingest.list_batches(BatchFilter(source_label="hostile"))
    (hostile_batch,) = batches.items
    assert len((await events.query(_query(batch_id=hostile_batch.batch_id))).items) == 2


async def test_asset_filter_uses_the_assets_networks(
    loaded: object, events: EventReadService, app_engine: AsyncEngine
) -> None:
    assets = AssetService(SqlAssetStore(make_session_factory(app_engine)))
    asset = await assets.create(
        AssetSpec.model_validate(
            {
                "hostname": "ws-11.lab.example.test",
                "environment": "lab",
                "networks": [{"cidr": "10.10.0.11/32"}],
            }
        )
    )
    page = await events.query(_query(asset_id=asset.id, limit=200))
    assert page.items, "ws-11 appears as a source in the fixtures"
    assert all(ip_address("10.10.0.11") in (row.src_ip, row.dest_ip) for row in page.items)
    assert (await events.query(_query(asset_id=uuid4()))).items == ()


async def test_keyset_pagination_walks_every_row_once(
    loaded: object, events: EventReadService
) -> None:
    seen: list[object] = []
    cursor: str | None = None
    pages = 0
    while True:
        page = await events.query(_query(limit=4, cursor=cursor))
        seen.extend(row.id for row in page.items)
        pages += 1
        if page.next_cursor is None:
            break
        cursor = page.next_cursor
    assert pages == 4 and len(seen) == 13 and len(set(seen)) == 13


async def test_payload_is_read_only_when_requested(
    loaded: object, events: EventReadService
) -> None:
    alert = (await events.query(_query(event_types=(EventType.alert,)))).items[0]
    with_payload = await events.get(alert.id, include_payload=True)
    assert with_payload.payload is not None and with_payload.payload["alert"]["gid"] == 1
    assert (await events.get(alert.id, include_payload=False)).payload is None
    page = await events.query(_query(event_types=(EventType.alert,), include_payload=True))
    assert page.items[0].payload == with_payload.payload


async def test_stats_count_by_type_and_hour(loaded: object, events: EventReadService) -> None:
    stats = await events.stats(_query())
    assert stats.total == 13
    assert dict(stats.by_type)["dns"] == 4 and dict(stats.by_type)["alert"] == 1
    assert [moment.hour for moment, _ in stats.by_hour] == [10]
    assert stats.by_hour[0][1] == 13
    assert (await events.stats(_query(event_types=(EventType.ssh,)))).total == 1


async def test_batches_and_rejects_are_listed_with_cursors(
    loaded: tuple[IngestService, list[str]],
) -> None:
    ingest, _ = loaded
    page = await ingest.list_batches(BatchFilter(limit=1))
    assert len(page.items) == 1 and page.next_cursor is not None
    assert page.items[0].source_label == "hostile"  # newest first
    rest = await ingest.list_batches(BatchFilter(limit=1, cursor=page.next_cursor))
    assert rest.items[0].source_label == "read-suite" and rest.next_cursor is None
    assert (await ingest.list_batches(BatchFilter(status=IngestStatus.failed))).items == ()

    hostile = page.items[0]
    first = await ingest.list_rejects(hostile.batch_id, limit=4)
    assert [row.line_number for row in first.items] == [3, 4, 5, 6]
    assert first.items[0].reason is RejectReason.missing_required
    assert first.next_cursor is not None
    second = await ingest.list_rejects(hostile.batch_id, limit=10, cursor=first.next_cursor)
    assert [row.line_number for row in second.items] == [7, 8, 9, 10, 11, 12]
    assert second.next_cursor is None
