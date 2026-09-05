"""Dramatiq actors. Messages carry ids only (ARCHITECTURE TB-5); the actor re-reads
everything it needs from the registry and the database.

``import_dataset`` is the first actor (Chunk 4). It runs the same ingest service the CLI
runs synchronously, against a batch row the enqueuing side has already opened, so a
caller can poll the batch by id from the moment the message is sent. It does not retry:
ingest is idempotent, so a re-run is always safe, but a failed batch should be visible as
``failed`` rather than silently re-attempted against a registry error.
"""

from __future__ import annotations

import asyncio
from uuid import UUID

import dramatiq

from aegisnet.adapters.db import engine as db_engine
from aegisnet.adapters.db.ingest_store import SqlIngestStore
from aegisnet.adapters.db.session import make_session_factory
from aegisnet.adapters.queue.names import IMPORT_DATASET_ACTOR, INGEST_QUEUE
from aegisnet.config import get_settings
from aegisnet.logging import get_logger
from aegisnet.services.ingest_service import IngestService, limits_from_settings

logger = get_logger(__name__)

IMPORT_TIME_LIMIT_MS = 30 * 60 * 1000


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
