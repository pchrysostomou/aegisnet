"""SQLAlchemy implementation of :class:`aegisnet.domain.ports.IngestStore`.

Runs as the runtime role, which holds INSERT and UPDATE on ``ingest_batches``,
``events`` and ``ingest_rejects`` and nothing more (ADR-012). Idempotency is the database's
job: ``INSERT ... ON CONFLICT (event_hash) DO NOTHING`` returns only the rows it created.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import insert, select, tuple_, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from aegisnet.adapters.db.models import Event, IngestBatch, IngestReject
from aegisnet.domain.enums import IngestStatus, RejectReason
from aegisnet.domain.models import NormalizedEvent
from aegisnet.domain.pagination import decode_int, decode_time_id, encode_int, encode_time_id
from aegisnet.domain.ports import (
    BatchCounts,
    BatchFilter,
    BatchProvenance,
    BatchSummary,
    Page,
    RejectedLine,
    RejectRow,
)


def event_row(batch_id: UUID, event: NormalizedEvent, ingested_at: datetime) -> dict[str, Any]:
    return {
        "batch_id": batch_id,
        "event_hash": event.event_hash,
        "event_time": event.event_time,
        "ingested_at": ingested_at,
        "event_type": event.event_type,
        "flow_id": event.flow_id,
        "src_ip": None if event.src_ip is None else str(event.src_ip),
        "dest_ip": None if event.dest_ip is None else str(event.dest_ip),
        "src_port": event.src_port,
        "dest_port": event.dest_port,
        "proto": event.proto,
        "app_proto": event.app_proto,
        "bytes_toserver": event.bytes_toserver,
        "bytes_toclient": event.bytes_toclient,
        "pkts_toserver": event.pkts_toserver,
        "pkts_toclient": event.pkts_toclient,
        "dns_query": event.dns_query,
        "dns_rrtype": event.dns_rrtype,
        "dns_rcode": event.dns_rcode,
        "http_host": event.http_host,
        "http_url_path": event.http_url_path,
        "sig_signature": event.sig_signature,
        "sig_category": event.sig_category,
        "sig_signature_id": event.sig_signature_id,
        "sig_severity": event.sig_severity,
        "payload": event.payload,
    }


class SqlIngestStore:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._sessions = session_factory

    async def open_batch(self, provenance: BatchProvenance, started_at: datetime) -> UUID:
        statement = (
            insert(IngestBatch)
            .values(
                source_type=provenance.source_type,
                source_label=provenance.source_label,
                ingest_method=provenance.ingest_method,
                dataset_id=provenance.dataset_id,
                dataset_licence=provenance.dataset_licence,
                dataset_citation=provenance.dataset_citation,
                actor_user_id=provenance.actor_user_id,
                actor_token_id=provenance.actor_token_id,
                status=IngestStatus.received,
                started_at=started_at,
                updated_at=started_at,
            )
            .returning(IngestBatch.id)
        )
        async with self._sessions() as session, session.begin():
            batch_id: UUID = (await session.execute(statement)).scalar_one()
            return batch_id

    async def mark_normalizing(self, batch_id: UUID) -> None:
        async with self._sessions() as session, session.begin():
            await session.execute(
                update(IngestBatch)
                .where(IngestBatch.id == batch_id)
                .values(status=IngestStatus.normalizing)
            )

    async def store_events(
        self, batch_id: UUID, events: Sequence[NormalizedEvent], ingested_at: datetime
    ) -> int:
        if not events:
            return 0
        rows = [event_row(batch_id, event, ingested_at) for event in events]
        statement = (
            pg_insert(Event)
            .values(rows)
            .on_conflict_do_nothing(index_elements=[Event.event_hash])
            .returning(Event.id)
        )
        async with self._sessions() as session, session.begin():
            inserted = (await session.execute(statement)).all()
            return len(inserted)

    async def store_rejects(self, batch_id: UUID, rejects: Sequence[RejectedLine]) -> None:
        if not rejects:
            return
        rows = [
            {
                "batch_id": batch_id,
                "line_number": item.line_number,
                "reason_code": item.reject.reason,
                "detail": item.reject.detail,
                "raw_excerpt": item.reject.raw_excerpt,
            }
            for item in rejects
        ]
        async with self._sessions() as session, session.begin():
            await session.execute(insert(IngestReject).values(rows))

    async def finish_batch(
        self, batch_id: UUID, status: IngestStatus, counts: BatchCounts, finished_at: datetime
    ) -> None:
        async with self._sessions() as session, session.begin():
            await session.execute(
                update(IngestBatch)
                .where(IngestBatch.id == batch_id)
                .values(
                    status=status,
                    events_received=counts.received,
                    events_stored=counts.stored,
                    events_duplicate=counts.duplicate,
                    events_rejected=counts.rejected,
                    finished_at=finished_at,
                    updated_at=finished_at,
                )
            )

    @staticmethod
    def _summary(row: IngestBatch) -> BatchSummary:
        return BatchSummary(
            batch_id=row.id,
            status=IngestStatus(row.status),
            source_label=row.source_label,
            dataset_id=row.dataset_id,
            counts=BatchCounts(
                received=row.events_received,
                stored=row.events_stored,
                duplicate=row.events_duplicate,
                rejected=row.events_rejected,
            ),
            started_at=row.started_at,
            finished_at=row.finished_at,
        )

    async def get_batch(self, batch_id: UUID) -> BatchSummary | None:
        async with self._sessions() as session:
            row = (
                await session.execute(select(IngestBatch).where(IngestBatch.id == batch_id))
            ).scalar_one_or_none()
        return None if row is None else self._summary(row)

    async def list_batches(self, query: BatchFilter) -> Page[BatchSummary]:
        statement = select(IngestBatch)
        if query.status is not None:
            statement = statement.where(IngestBatch.status == query.status)
        if query.source_label is not None:
            statement = statement.where(IngestBatch.source_label == query.source_label)
        if query.time_from is not None:
            statement = statement.where(IngestBatch.started_at >= query.time_from)
        if query.time_to is not None:
            statement = statement.where(IngestBatch.started_at <= query.time_to)
        if query.cursor is not None:
            moment, last_id = decode_time_id(query.cursor)
            statement = statement.where(
                tuple_(IngestBatch.started_at, IngestBatch.id) < (moment, last_id)
            )
        statement = statement.order_by(IngestBatch.started_at.desc(), IngestBatch.id.desc()).limit(
            query.limit + 1
        )
        async with self._sessions() as session:
            rows = list((await session.execute(statement)).scalars())
        has_more = len(rows) > query.limit
        rows = rows[: query.limit]
        next_cursor = encode_time_id(rows[-1].started_at, rows[-1].id) if has_more else None
        return Page(items=tuple(self._summary(row) for row in rows), next_cursor=next_cursor)

    async def list_rejects(
        self, batch_id: UUID, *, limit: int, cursor: str | None
    ) -> Page[RejectRow]:
        statement = select(IngestReject).where(IngestReject.batch_id == batch_id)
        if cursor is not None:
            statement = statement.where(IngestReject.line_number > decode_int(cursor))
        statement = statement.order_by(IngestReject.line_number).limit(limit + 1)
        async with self._sessions() as session:
            rows = list((await session.execute(statement)).scalars())
        has_more = len(rows) > limit
        rows = rows[:limit]
        items = tuple(
            RejectRow(
                line_number=row.line_number,
                reason=RejectReason(row.reason_code),
                detail=row.detail,
                raw_excerpt=row.raw_excerpt,
                created_at=row.created_at,
            )
            for row in rows
        )
        next_cursor = encode_int(rows[-1].line_number) if has_more else None
        return Page(items=items, next_cursor=next_cursor)
