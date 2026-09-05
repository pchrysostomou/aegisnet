"""Ports: what a use-case needs from the outside world, as Protocols and value objects.

Ports are abstract and pure, so they live in the domain: services call them, adapters
implement them, and the layering contract (entrypoints over services over adapters over
domain) holds in both directions (ADR-014). The ingest service writes through
:class:`IngestStore`; the production implementation is
:class:`aegisnet.adapters.db.ingest_store.SqlIngestStore`, tests use an in-memory fake.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol
from uuid import UUID

from aegisnet.domain.enums import IngestMethod, IngestStatus, SourceType
from aegisnet.domain.models import NormalizedEvent, Reject


@dataclass(frozen=True, slots=True)
class BatchProvenance:
    """Who loaded what, from where (FR-1.6, T-1.8). Actor ids arrive with Chunk 6."""

    source_type: SourceType
    source_label: str
    ingest_method: IngestMethod
    dataset_id: str | None = None
    dataset_licence: str | None = None
    dataset_citation: str | None = None
    actor_user_id: UUID | None = None
    actor_token_id: UUID | None = None


@dataclass(frozen=True, slots=True)
class BatchCounts:
    received: int = 0
    stored: int = 0
    duplicate: int = 0
    rejected: int = 0


@dataclass(frozen=True, slots=True)
class BatchSummary:
    batch_id: UUID
    status: IngestStatus
    source_label: str
    dataset_id: str | None
    counts: BatchCounts
    started_at: datetime
    finished_at: datetime | None


@dataclass(frozen=True, slots=True)
class RejectedLine:
    line_number: int
    reject: Reject


class IngestStore(Protocol):
    """Persistence for one ingest batch. Every method is one short transaction."""

    async def open_batch(self, provenance: BatchProvenance, started_at: datetime) -> UUID: ...

    async def mark_normalizing(self, batch_id: UUID) -> None: ...

    async def store_events(
        self, batch_id: UUID, events: Sequence[NormalizedEvent], ingested_at: datetime
    ) -> int:
        """Insert, skipping any ``event_hash`` already present. Returns how many were new."""
        ...

    async def store_rejects(self, batch_id: UUID, rejects: Sequence[RejectedLine]) -> None: ...

    async def finish_batch(
        self, batch_id: UUID, status: IngestStatus, counts: BatchCounts, finished_at: datetime
    ) -> None: ...

    async def get_batch(self, batch_id: UUID) -> BatchSummary | None: ...
