"""Ingest use-case: lines in, a finished batch out (FR-1.4, FR-1.5, FR-1.6).

Streams NDJSON line by line, never holding a whole file. Each line goes through the pure
normaliser; events are written in chunks with ``INSERT ... ON CONFLICT DO NOTHING`` on
``event_hash`` so a re-ingest stores nothing new and reports every line as a duplicate;
rejects are written per line with their reason code; the batch row records the counts,
the provenance and the outcome. A bad line never fails the batch. Exceeding the line
budget does: the batch is marked ``failed`` and :class:`IngestLimitExceededError` is
raised, with whatever was stored before the limit left in place (it was valid).

The clock is injected so tests are deterministic; ``started_at`` is captured once per
batch and is also the reference for the timestamp sanity window (T-1.7).
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Final
from uuid import UUID

from aegisnet.adapters.files.registry import (
    RegistryError,
    ResolvedDataset,
    load_registry,
    resolve_dataset,
)
from aegisnet.config import Settings
from aegisnet.domain.enums import IngestMethod, IngestStatus, SourceType
from aegisnet.domain.eve.limits import ParseLimits
from aegisnet.domain.eve.normalizer import TimestampWindow, normalize_line
from aegisnet.domain.models import NormalizedEvent, Reject
from aegisnet.domain.pagination import check_limit, decode_int, decode_time_id
from aegisnet.domain.ports import (
    BatchCounts,
    BatchFilter,
    BatchProvenance,
    BatchSummary,
    IngestStore,
    Page,
    RejectedLine,
    RejectRow,
)
from aegisnet.logging import get_logger

logger = get_logger(__name__)

DEFAULT_CHUNK_SIZE: Final = 500
DEFAULT_LIMIT_ROWS: Final = 50


class IngestLimitExceededError(Exception):
    """The batch broke a batch-level limit (line count). Per-line limits never raise."""


class BatchNotFoundError(Exception):
    pass


def utc_now() -> datetime:
    return datetime.now(tz=UTC)


@dataclass(frozen=True, slots=True)
class IngestLimits:
    max_lines: int
    parse: ParseLimits
    window: TimestampWindow


class IngestService:
    def __init__(
        self,
        store: IngestStore,
        limits: IngestLimits,
        *,
        clock: Callable[[], datetime] = utc_now,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
    ) -> None:
        if chunk_size < 1:
            raise ValueError("chunk_size must be positive")
        self._store = store
        self._limits = limits
        self._clock = clock
        self._chunk_size = chunk_size

    # ---------------------------------------------------------------- batches
    async def open_batch(self, provenance: BatchProvenance) -> UUID:
        """Create the batch row ahead of processing, e.g. before enqueueing async work."""
        return await self._store.open_batch(provenance, self._clock())

    async def get_batch(self, batch_id: UUID) -> BatchSummary | None:
        return await self._store.get_batch(batch_id)

    async def list_batches(self, query: BatchFilter) -> Page[BatchSummary]:
        check_limit(query.limit)
        if query.cursor is not None:
            decode_time_id(query.cursor)
        return await self._store.list_batches(query)

    async def list_rejects(
        self, batch_id: UUID, *, limit: int = DEFAULT_LIMIT_ROWS, cursor: str | None = None
    ) -> Page[RejectRow]:
        check_limit(limit)
        if cursor is not None:
            decode_int(cursor)
        if await self._store.get_batch(batch_id) is None:
            raise BatchNotFoundError("unknown batch")
        return await self._store.list_rejects(batch_id, limit=limit, cursor=cursor)

    async def ingest(
        self,
        lines: Iterable[bytes | str],
        provenance: BatchProvenance | None = None,
        *,
        batch_id: UUID | None = None,
    ) -> BatchSummary:
        started_at = self._clock()
        if batch_id is None:
            if provenance is None:
                raise ValueError("a new batch needs its provenance")
            batch_id = await self._store.open_batch(provenance, started_at)
        await self._store.mark_normalizing(batch_id)

        counts = BatchCounts()
        status = IngestStatus.complete
        events: list[NormalizedEvent] = []
        rejects: list[RejectedLine] = []
        limit_hit = False
        try:
            for line_number, raw in enumerate(lines, start=1):
                text = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else raw
                if not text.strip():
                    continue
                if counts.received >= self._limits.max_lines:
                    limit_hit = True
                    break
                counts = _bump(counts, received=1)
                outcome = normalize_line(
                    text,
                    now=started_at,
                    limits=self._limits.parse,
                    window=self._limits.window,
                )
                if isinstance(outcome, Reject):
                    rejects.append(RejectedLine(line_number, outcome))
                else:
                    events.append(outcome)
                if len(events) >= self._chunk_size or len(rejects) >= self._chunk_size:
                    counts = await self._flush(batch_id, events, rejects, counts)
            counts = await self._flush(batch_id, events, rejects, counts)
        except Exception:
            status = IngestStatus.failed
            logger.error(
                "ingest_batch_failed",
                extra={"batch_id": str(batch_id), "received": counts.received},
                exc_info=True,
            )
            await self._store.finish_batch(batch_id, status, counts, self._clock())
            raise
        if limit_hit:
            status = IngestStatus.failed
        await self._store.finish_batch(batch_id, status, counts, self._clock())
        logger.info(
            "ingest_batch_finished",
            extra={
                "batch_id": str(batch_id),
                "status": status.value,
                "received": counts.received,
                "stored": counts.stored,
                "duplicate": counts.duplicate,
                "rejected": counts.rejected,
            },
        )
        if limit_hit:
            raise IngestLimitExceededError(
                f"batch exceeds the {self._limits.max_lines}-line limit; "
                f"marked failed after {counts.received} lines"
            )
        summary = await self._store.get_batch(batch_id)
        if summary is None:  # pragma: no cover - the row was written moments ago
            raise RuntimeError("batch vanished during ingest")
        return summary

    async def _flush(
        self,
        batch_id: UUID,
        events: list[NormalizedEvent],
        rejects: list[RejectedLine],
        counts: BatchCounts,
    ) -> BatchCounts:
        if events:
            unique = _dedupe(events)
            stored = await self._store.store_events(batch_id, unique, self._clock())
            counts = _bump(counts, stored=stored, duplicate=len(events) - stored)
            events.clear()
        if rejects:
            await self._store.store_rejects(batch_id, rejects)
            counts = _bump(counts, rejected=len(rejects))
            rejects.clear()
        return counts

    # ---------------------------------------------------------------- datasets
    def resolve(self, samples_dir: Path, dataset_id: str) -> ResolvedDataset:
        """Registry lookup with path confinement and checksum (T-1.6); raises RegistryError."""
        return resolve_dataset(samples_dir, load_registry(samples_dir), dataset_id)

    async def import_dataset(
        self,
        samples_dir: Path,
        dataset_id: str,
        *,
        source_label: str,
        batch_id: UUID | None = None,
        actor_user_id: UUID | None = None,
        actor_token_id: UUID | None = None,
    ) -> BatchSummary:
        """Ingest a registered dataset. With ``batch_id`` (the async path) a batch row already
        exists; a registry failure then marks it failed instead of leaving it ``received``."""
        try:
            resolved = self.resolve(samples_dir, dataset_id)
        except RegistryError:
            if batch_id is not None:
                await self._store.finish_batch(
                    batch_id, IngestStatus.failed, BatchCounts(), self._clock()
                )
            raise
        provenance = provenance_for(
            resolved, source_label, actor_user_id=actor_user_id, actor_token_id=actor_token_id
        )
        with resolved.path.open("rb") as handle:
            return await self.ingest(handle, provenance, batch_id=batch_id)


def provenance_for(
    resolved: ResolvedDataset,
    source_label: str,
    *,
    actor_user_id: UUID | None = None,
    actor_token_id: UUID | None = None,
) -> BatchProvenance:
    return BatchProvenance(
        source_type=SourceType.suricata_eve,
        source_label=source_label,
        ingest_method=IngestMethod.registry_import,
        dataset_id=resolved.entry.id,
        dataset_licence=resolved.entry.licence,
        dataset_citation=resolved.entry.citation,
        actor_user_id=actor_user_id,
        actor_token_id=actor_token_id,
    )


def limits_from_settings(settings: Settings) -> IngestLimits:
    return IngestLimits(
        max_lines=settings.ingest_max_lines,
        parse=ParseLimits(
            max_line_bytes=settings.ingest_max_line_bytes,
            max_json_depth=settings.ingest_max_json_depth,
            max_keys_per_object=settings.ingest_max_keys_per_object,
        ),
        window=TimestampWindow(
            max_past=timedelta(days=settings.ingest_timestamp_max_past_days),
            max_future=timedelta(hours=settings.ingest_timestamp_max_future_hours),
        ),
    )


def _bump(
    counts: BatchCounts,
    *,
    received: int = 0,
    stored: int = 0,
    duplicate: int = 0,
    rejected: int = 0,
) -> BatchCounts:
    return BatchCounts(
        received=counts.received + received,
        stored=counts.stored + stored,
        duplicate=counts.duplicate + duplicate,
        rejected=counts.rejected + rejected,
    )


def _dedupe(events: list[NormalizedEvent]) -> list[NormalizedEvent]:
    """First occurrence wins within a chunk; the database handles everything else."""
    seen: set[bytes] = set()
    unique: list[NormalizedEvent] = []
    for event in events:
        if event.event_hash not in seen:
            seen.add(event.event_hash)
            unique.append(event)
    return unique
