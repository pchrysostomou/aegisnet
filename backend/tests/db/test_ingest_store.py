"""The SQL ingest store and the worker actor against a real PostgreSQL 16."""

from __future__ import annotations

import importlib
import json
from collections.abc import AsyncIterator
from datetime import UTC, datetime

import dramatiq
import pytest
from dramatiq import Worker
from dramatiq.brokers.stub import StubBroker
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from aegisnet.adapters.db.ingest_store import SqlIngestStore
from aegisnet.adapters.db.session import make_session_factory
from aegisnet.adapters.queue.ingest_queue import RedisIngestQueue
from aegisnet.adapters.queue.names import IMPORT_DATASET_ACTOR, INGEST_QUEUE
from aegisnet.config import Settings, get_settings
from aegisnet.domain.enums import IngestMethod, IngestStatus, RejectReason, SourceType
from aegisnet.domain.ports import BatchCounts, BatchProvenance
from aegisnet.services.ingest_service import IngestService, limits_from_settings, provenance_for
from tests.conftest import REPO_ROOT

pytestmark = [pytest.mark.db, pytest.mark.integration]

SAMPLES = REPO_ROOT / "samples"
FIXTURES = REPO_ROOT / "backend" / "tests" / "fixtures" / "eve"
DATASET_ID = "synthetic-benign-baseline-01"
NOW = datetime(2026, 9, 5, 12, 0, tzinfo=UTC)
PROVENANCE = BatchProvenance(
    source_type=SourceType.suricata_eve,
    source_label="db-suite",
    ingest_method=IngestMethod.api_ndjson,
)


@pytest.fixture(autouse=True)
async def clean_tables(migrator_engine: AsyncEngine) -> AsyncIterator[None]:
    """The app role holds no DELETE, so the owner clears the ingest tables between tests."""
    async with migrator_engine.begin() as connection:
        await connection.execute(text("DELETE FROM ingest_rejects"))
        await connection.execute(text("DELETE FROM events"))
        await connection.execute(text("DELETE FROM ingest_batches"))
    yield


@pytest.fixture
def service(app_engine: AsyncEngine, db_settings: Settings) -> IngestService:
    store = SqlIngestStore(make_session_factory(app_engine))
    return IngestService(store, limits_from_settings(db_settings), clock=lambda: NOW)


async def _count(engine: AsyncEngine, table: str) -> int:
    async with engine.connect() as connection:
        value = (await connection.execute(text(f"SELECT count(*) FROM {table}"))).scalar_one()  # noqa: S608 - literal
        return int(value)


async def test_corpus_import_is_idempotent_and_matches_the_manifest(
    service: IngestService, app_engine: AsyncEngine
) -> None:
    entry = service.resolve(SAMPLES, DATASET_ID).entry
    assert entry.manifest is not None
    manifest = json.loads((SAMPLES / entry.manifest).read_text())

    first = await service.import_dataset(SAMPLES, DATASET_ID, source_label="demo-1")
    assert first.status is IngestStatus.complete
    assert first.counts == BatchCounts(received=2000, stored=2000, duplicate=0, rejected=0)
    assert first.dataset_id == DATASET_ID
    assert await _count(app_engine, "events") == 2000

    async with app_engine.connect() as connection:
        rows = (
            await connection.execute(
                text("SELECT event_type::text, count(*) FROM events GROUP BY 1 ORDER BY 1")
            )
        ).all()
    assert dict(rows) == manifest["counts_by_type"]

    second = await service.import_dataset(SAMPLES, DATASET_ID, source_label="demo-2")
    assert second.counts == BatchCounts(received=2000, stored=0, duplicate=2000, rejected=0)
    assert await _count(app_engine, "events") == 2000
    assert await _count(app_engine, "ingest_batches") == 2


async def test_batch_row_carries_provenance_and_timestamps(
    service: IngestService, app_engine: AsyncEngine
) -> None:
    summary = await service.import_dataset(SAMPLES, DATASET_ID, source_label="prov")
    async with app_engine.connect() as connection:
        row = (
            await connection.execute(
                text(
                    "SELECT source_type::text, ingest_method::text, dataset_id, dataset_licence, "
                    "dataset_citation, status::text, started_at, finished_at, actor_user_id "
                    "FROM ingest_batches WHERE id = :id"
                ),
                {"id": summary.batch_id},
            )
        ).one()
    assert row[:3] == ("suricata_eve", "registry_import", DATASET_ID)
    assert row.dataset_licence.startswith("MIT")
    assert row.dataset_citation is None
    assert row.status == "complete"
    assert row.started_at == row.finished_at == NOW
    assert row.actor_user_id is None


async def test_rejects_are_persisted_with_line_numbers_and_reasons(
    service: IngestService, app_engine: AsyncEngine
) -> None:
    lines = (FIXTURES / "hostile.ndjson").read_text(encoding="utf-8").splitlines()
    summary = await service.ingest(lines, PROVENANCE)
    assert summary.counts == BatchCounts(received=12, stored=2, duplicate=0, rejected=10)
    async with app_engine.connect() as connection:
        rows = (
            await connection.execute(
                text(
                    "SELECT line_number, reason_code::text, detail, raw_excerpt "
                    "FROM ingest_rejects WHERE batch_id = :id ORDER BY line_number"
                ),
                {"id": summary.batch_id},
            )
        ).all()
    assert [r.line_number for r in rows] == list(range(3, 13))
    assert rows[0].reason_code == RejectReason.missing_required.value
    assert rows[7].reason_code == RejectReason.json_parse.value
    assert all(len(r.detail) <= 512 and len(r.raw_excerpt) <= 256 for r in rows)
    assert all("\x1b" not in r.raw_excerpt for r in rows)


async def test_promoted_columns_match_the_normaliser(
    service: IngestService, app_engine: AsyncEngine
) -> None:
    lines = (FIXTURES / "benign.ndjson").read_text(encoding="utf-8").splitlines()
    await service.ingest(lines, PROVENANCE)
    async with app_engine.connect() as connection:
        alert = (
            await connection.execute(
                text(
                    "SELECT event_type::text, host(src_ip) AS src, dest_port, sig_signature_id, "
                    "sig_severity, http_host, bytes_toclient, payload->'alert'->>'gid' AS gid, "
                    "octet_length(event_hash) AS hash_len, ingested_at "
                    "FROM events WHERE sig_signature_id = 9000001"
                )
            )
        ).one()
        answer = (
            await connection.execute(
                text(
                    "SELECT dns_query, dns_rrtype, dns_rcode FROM events "
                    "WHERE dns_rcode IS NOT NULL"
                )
            )
        ).one()
    assert alert[:7] == ("alert", "10.10.0.11", 80, 9000001, 3, "www.example.test", 1200)
    assert (alert.gid, alert.hash_len, alert.ingested_at) == ("1", 32, NOW)
    assert tuple(answer) == ("cdn.example.test", "A", "NOERROR")


async def test_the_actor_imports_a_pre_opened_batch_through_a_stub_broker(
    service: IngestService, app_engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """End to end: the CLI's async path opens the batch and enqueues by name; the worker's
    actor, bound to whichever broker is installed, finishes it."""
    monkeypatch.setenv("SAMPLES_DIR", str(SAMPLES))
    get_settings.cache_clear()
    previous = dramatiq.get_broker()
    broker = StubBroker()
    dramatiq.set_broker(broker)
    try:
        from aegisnet.workers import actors

        if IMPORT_DATASET_ACTOR not in broker.get_declared_actors():
            importlib.reload(actors)  # re-run the decorator against the stub broker
        assert IMPORT_DATASET_ACTOR in broker.get_declared_actors()

        batch_id = await service.open_batch(
            provenance_for(service.resolve(SAMPLES, DATASET_ID), "actor-run")
        )
        RedisIngestQueue(broker).enqueue_import(batch_id, DATASET_ID, "actor-run")  # type: ignore[arg-type]

        worker = Worker(broker, worker_timeout=100, worker_threads=1)
        worker.start()
        try:
            broker.join(INGEST_QUEUE)
            worker.join()
        finally:
            worker.stop()
    finally:
        dramatiq.set_broker(previous)
        get_settings.cache_clear()

    summary = await service.get_batch(batch_id)
    assert summary is not None
    assert summary.status is IngestStatus.complete
    assert summary.counts == BatchCounts(received=2000, stored=2000, duplicate=0, rejected=0)
    assert summary.source_label == "actor-run"
    assert await _count(app_engine, "events") == 2000
