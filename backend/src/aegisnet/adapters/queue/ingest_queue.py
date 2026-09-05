"""Enqueue ingest work by actor name. Messages carry ids and a label, never data (TB-5)."""

from __future__ import annotations

from typing import Any
from uuid import UUID

import dramatiq
from dramatiq.brokers.redis import RedisBroker

from aegisnet.adapters.queue.names import IMPORT_DATASET_ACTOR, INGEST_QUEUE


class RedisIngestQueue:
    def __init__(self, broker: RedisBroker) -> None:
        self._broker = broker

    def enqueue_import(self, batch_id: UUID, dataset_id: str, source_label: str) -> str:
        """Queue ``import_dataset`` for an already-opened batch; returns the message id."""
        message: Any = dramatiq.Message(
            queue_name=INGEST_QUEUE,
            actor_name=IMPORT_DATASET_ACTOR,
            args=(str(batch_id), dataset_id, source_label),
            kwargs={},
            options={},
        )
        # Dramatiq ships no annotations; the enqueue returns the message it stored.
        stored = self._broker.enqueue(message)  # type: ignore[no-untyped-call]
        return str(stored.message_id)
