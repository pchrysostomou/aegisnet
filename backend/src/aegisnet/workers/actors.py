"""Dramatiq actors. Messages carry ids only (ARCHITECTURE TB-5); the actor re-reads
everything it needs from the registry and the database.

``import_dataset`` is the first actor (Chunk 4). It runs the same ingest service the CLI
runs synchronously, against a batch row the enqueuing side has already opened, so a
caller can poll the batch by id from the moment the message is sent. It does not retry:
ingest is idempotent, so a re-run is always safe, but a failed batch should be visible as
``failed`` rather than silently re-attempted against a registry error.

A batch that completes with stored events queues the post-ingest sweep over its span
(ADR-020) unless ``POST_INGEST_SWEEP`` is off. The periodic actors are in ``schedule``.
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from uuid import UUID

import dramatiq
from sqlalchemy.ext.asyncio import AsyncEngine

from aegisnet.adapters.db import engine as db_engine
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
from aegisnet.adapters.files.spool import Spool
from aegisnet.adapters.queue.detection_queue import RedisDetectionQueue
from aegisnet.adapters.queue.names import (
    DETECTION_QUEUE,
    IMPORT_DATASET_ACTOR,
    IMPORT_UPLOAD_ACTOR,
    INGEST_QUEUE,
    RECOMPUTE_BASELINES_ACTOR,
    RUN_DETECTORS_ACTOR,
)
from aegisnet.config import Settings, get_settings
from aegisnet.domain.enums import IngestStatus
from aegisnet.domain.ports import BatchSummary
from aegisnet.logging import get_logger
from aegisnet.services.asset_service import AssetService
from aegisnet.services.baseline_service import BaselineService
from aegisnet.services.detection_service import DetectionService, describe
from aegisnet.services.ingest_service import IngestService, limits_from_settings
from aegisnet.services.schedule import sweep_batch

logger = get_logger(__name__)

IMPORT_TIME_LIMIT_MS = 30 * 60 * 1000


async def sweep_after(summary: BatchSummary, engine: AsyncEngine, settings: Settings) -> int:
    """Queue the post-ingest sweep for a completed batch; returns how many were queued."""
    if not settings.post_ingest_sweep or summary.status is not IngestStatus.complete:
        return 0
    if summary.counts.stored == 0:
        return 0
    queue = RedisDetectionQueue(dramatiq.get_broker())

    async def enqueue(start: datetime, end: datetime) -> str:
        return queue.enqueue_sweep(start, end)

    intervals = await sweep_batch(
        SqlEventReadStore(make_session_factory(engine)), summary.batch_id, enqueue
    )
    logger.info(
        "post_ingest_sweep_queued",
        extra={"batch_id": str(summary.batch_id), "sweeps": len(intervals)},
    )
    return len(intervals)


async def run_import(batch_id: UUID, dataset_id: str, source_label: str) -> None:
    settings = get_settings()
    engine = db_engine.create_engine(settings)
    try:
        service = IngestService(
            SqlIngestStore(make_session_factory(engine)), limits_from_settings(settings)
        )
        summary = await service.import_dataset(
            settings.samples_dir, dataset_id, source_label=source_label, batch_id=batch_id
        )
        logger.info(
            "import_dataset_done",
            extra={
                "batch_id": str(summary.batch_id),
                "status": summary.status.value,
                "stored": summary.counts.stored,
                "duplicate": summary.counts.duplicate,
                "rejected": summary.counts.rejected,
            },
        )
        await sweep_after(summary, engine, settings)
    finally:
        await db_engine.dispose(engine)


@dramatiq.actor(
    actor_name=IMPORT_DATASET_ACTOR,
    queue_name=INGEST_QUEUE,
    max_retries=0,
    time_limit=IMPORT_TIME_LIMIT_MS,
)
def import_dataset(batch_id: str, dataset_id: str, source_label: str) -> None:
    asyncio.run(run_import(UUID(batch_id), dataset_id, source_label))


async def run_upload(batch_id: UUID, spool_name: str) -> None:
    """Finish a batch the API opened from a spooled upload; the spool entry is removed
    afterwards whether the batch completed or failed."""
    settings = get_settings()
    spool = Spool(settings.spool_dir)
    spool.ensure_writable()
    engine = db_engine.create_engine(settings)
    try:
        service = IngestService(
            SqlIngestStore(make_session_factory(engine)), limits_from_settings(settings)
        )
        try:
            summary = await service.ingest(spool.lines(spool_name), batch_id=batch_id)
        finally:
            spool.remove(spool_name)
        logger.info(
            "import_upload_done",
            extra={
                "batch_id": str(summary.batch_id),
                "status": summary.status.value,
                "stored": summary.counts.stored,
                "duplicate": summary.counts.duplicate,
                "rejected": summary.counts.rejected,
            },
        )
        await sweep_after(summary, engine, settings)
    finally:
        await db_engine.dispose(engine)


@dramatiq.actor(
    actor_name=IMPORT_UPLOAD_ACTOR,
    queue_name=INGEST_QUEUE,
    max_retries=0,
    time_limit=IMPORT_TIME_LIMIT_MS,
)
def import_upload(batch_id: str, spool_name: str, source_label: str) -> None:
    asyncio.run(run_upload(UUID(batch_id), spool_name))


async def run_sweep(window_start: datetime, window_end: datetime) -> None:
    """One detection sweep over ``[window_start, window_end)`` (ADR-018)."""
    settings = get_settings()
    engine = db_engine.create_engine(settings)
    try:
        sessions = make_session_factory(engine)
        service = DetectionService(
            SqlRuleStore(sessions),
            SqlDetectorRunStore(sessions),
            SqlAlertStore(sessions),
            SqlEventReadStore(sessions),
            AssetService(SqlAssetStore(sessions)),
            baselines=SqlBaselineStore(sessions),
        )
        outcome = await service.sweep(window_start, window_end)
        logger.info(
            "run_detectors_done",
            extra={
                "events_examined": outcome.events_examined,
                "alerts_created": outcome.alerts_created,
                "runs": [(run.rule_id, run.status.value) for run in outcome.runs],
            },
        )
        _ = describe(outcome)
    finally:
        await db_engine.dispose(engine)


@dramatiq.actor(
    actor_name=RUN_DETECTORS_ACTOR,
    queue_name=DETECTION_QUEUE,
    max_retries=0,
    time_limit=IMPORT_TIME_LIMIT_MS,
)
def run_detectors(window_start: str, window_end: str) -> None:
    asyncio.run(run_sweep(datetime.fromisoformat(window_start), datetime.fromisoformat(window_end)))


async def run_baselines(window_days: int) -> None:
    """Recompute ``asset_baselines`` over the last ``window_days`` (ADR-019)."""
    settings = get_settings()
    engine = db_engine.create_engine(settings)
    try:
        sessions = make_session_factory(engine)
        service = BaselineService(
            SqlAssetStore(sessions),
            SqlEventReadStore(sessions),
            SqlBaselineStore(sessions),
            window_days=window_days,
        )
        run = await service.recompute()
        logger.info(
            "recompute_baselines_done",
            extra={
                "assets": run.assets_considered,
                "written": run.baselines_written,
                "window_days": run.window_days,
            },
        )
    finally:
        await db_engine.dispose(engine)


@dramatiq.actor(
    actor_name=RECOMPUTE_BASELINES_ACTOR,
    queue_name=DETECTION_QUEUE,
    max_retries=0,
    time_limit=IMPORT_TIME_LIMIT_MS,
)
def recompute_baselines(window_days: int) -> None:
    asyncio.run(run_baselines(int(window_days)))
