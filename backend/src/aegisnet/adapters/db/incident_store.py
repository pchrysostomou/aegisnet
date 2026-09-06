"""SQL implementation of the incident ports (Milestone 3, revision 0004; ADR-023).

Two constraints do the work that would otherwise need a lock. ``incident_alerts`` has a
UNIQUE on ``alert_id``, so an alert belongs to exactly one case however many times
correlation runs; and ``incident_timeline`` has a UNIQUE on
``(incident_id, entry_type, alert_id)``, so a case says the same thing about an alert once.
Both inserts are ``ON CONFLICT DO NOTHING``, which is what makes a re-run a no-op rather than
a duplicate — the property `docs/delivery-plan.md` M3 asks for.

The case number comes from a sequence rather than from a count, because two runs asking for
"the next one" at the same moment must not both get it.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import replace
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import func, select, text, tuple_, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from aegisnet.adapters.db.detection_store import alert_record
from aegisnet.adapters.db.models import (
    Alert,
    DetectionRule,
    Incident,
    IncidentAlert,
    IncidentNote,
    IncidentTimelineEntry,
)
from aegisnet.domain.enums import AlertStatus, IncidentAlertSource, IncidentStatus
from aegisnet.domain.incidents import CLOSED_STATUSES, case_number, is_closed
from aegisnet.domain.pagination import decode_time_id, encode_time_id
from aegisnet.domain.ports import (
    DETAIL_TIMELINE_LIMIT,
    AlertRecord,
    IncidentDetail,
    IncidentFilter,
    IncidentRecord,
    NewIncident,
    NewTimelineEntry,
    NoteRecord,
    Page,
    TimelineEntryRecord,
)

CASE_SEQUENCE = "incident_case_seq"
_CLOSED = tuple(status.value for status in sorted(CLOSED_STATUSES, key=lambda s: s.value))


def _incident(row: Incident) -> IncidentRecord:
    return IncidentRecord(
        id=row.id,
        case_number=row.case_number,
        title=row.title,
        severity=row.severity,
        severity_rationale=dict(row.severity_rationale),
        status=row.status,
        primary_asset_id=row.primary_asset_id,
        correlation_key=row.correlation_key,
        window_start=row.window_start,
        window_end=row.window_end,
        distinct_rule_count=row.distinct_rule_count,
        assigned_to=row.assigned_to,
        closed_at=row.closed_at,
        closure_reason=row.closure_reason,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _note(row: IncidentNote) -> NoteRecord:
    return NoteRecord(
        id=row.id,
        incident_id=row.incident_id,
        author_id=row.author_id,
        body=row.body,
        created_at=row.created_at,
    )


def _entry(row: IncidentTimelineEntry) -> TimelineEntryRecord:
    return TimelineEntryRecord(
        id=row.id,
        incident_id=row.incident_id,
        occurred_at=row.occurred_at,
        entry_type=row.entry_type,
        summary=row.summary,
        detail=dict(row.detail),
        alert_id=row.alert_id,
        actor_user_id=row.actor_user_id,
        created_at=row.created_at,
    )


class SqlIncidentStore:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._sessions = session_factory

    async def open_case(
        self,
        incident: NewIncident,
        entries: Sequence[NewTimelineEntry],
        *,
        now: datetime,
        source: IncidentAlertSource = IncidentAlertSource.correlation_engine,
    ) -> IncidentRecord:
        async with self._sessions() as session, session.begin():
            ordinal = (
                await session.execute(select(func.nextval(text(f"'{CASE_SEQUENCE}'"))))
            ).scalar_one()
            row = Incident(
                case_number=case_number(now.year, int(ordinal)),
                title=incident.title,
                severity=incident.severity,
                severity_rationale=incident.severity_rationale,
                status=IncidentStatus.new,
                primary_asset_id=incident.primary_asset_id,
                correlation_key=incident.correlation_key,
                window_start=incident.window_start,
                window_end=incident.window_end,
                distinct_rule_count=incident.distinct_rule_count,
                created_at=now,
                updated_at=now,
            )
            session.add(row)
            await session.flush()
            await self._link(session, row.id, incident.alert_ids, source=source, now=now)
            await self._append(session, row.id, entries, now=now)
            await session.refresh(row)
            return _incident(row)

    async def newest_open_for_key(self, correlation_key: str) -> IncidentRecord | None:
        statement = (
            select(Incident)
            .where(
                Incident.correlation_key == correlation_key,
                Incident.status.notin_(_CLOSED),
            )
            .order_by(Incident.window_end.desc(), Incident.created_at.desc())
            .limit(1)
        )
        async with self._sessions() as session:
            row = (await session.execute(statement)).scalar_one_or_none()
            return None if row is None else _incident(row)

    async def newest_closed_for_key(self, correlation_key: str) -> IncidentRecord | None:
        statement = (
            select(Incident)
            .where(Incident.correlation_key == correlation_key, Incident.status.in_(_CLOSED))
            .order_by(Incident.window_end.desc(), Incident.created_at.desc())
            .limit(1)
        )
        async with self._sessions() as session:
            row = (await session.execute(statement)).scalar_one_or_none()
            return None if row is None else _incident(row)

    async def extend(
        self,
        incident_id: UUID,
        alert_ids: Sequence[UUID],
        entries: Sequence[NewTimelineEntry],
        *,
        severity: int,
        severity_rationale: dict[str, Any],
        title: str,
        window_end: datetime,
        distinct_rule_count: int,
        now: datetime,
        source: IncidentAlertSource = IncidentAlertSource.correlation_engine,
    ) -> int:
        async with self._sessions() as session, session.begin():
            # Correlation read this case as open in an earlier transaction. Between then and
            # now an analyst may have closed it, and a closed case never absorbs a new alert
            # (ADR-023) — so the status is re-read under a row lock, which serialises against
            # the compare-and-set in `set_status`. Linking anyway would be permanent: the
            # alert would flip to `correlated`, and neither the open queue nor a later
            # correlation run would ever surface it again.
            status = (
                await session.execute(
                    select(Incident.status).where(Incident.id == incident_id).with_for_update()
                )
            ).scalar_one_or_none()
            if status is None or status in _CLOSED:
                return 0
            linked = await self._link(session, incident_id, alert_ids, source=source, now=now)
            await self._append(session, incident_id, entries, now=now)
            if linked:
                await session.execute(
                    update(Incident)
                    .where(Incident.id == incident_id)
                    .values(
                        severity=severity,
                        severity_rationale=severity_rationale,
                        title=title,
                        # A window grows and never shrinks.
                        window_end=func.greatest(Incident.window_end, window_end),
                        distinct_rule_count=distinct_rule_count,
                        updated_at=now,
                    )
                )
            return linked

    async def already_linked(self, alert_ids: Sequence[UUID]) -> set[UUID]:
        if not alert_ids:
            return set()
        statement = select(IncidentAlert.alert_id).where(IncidentAlert.alert_id.in_(alert_ids))
        async with self._sessions() as session:
            return set((await session.execute(statement)).scalars().all())

    async def set_status(
        self,
        incident_id: UUID,
        *,
        expected: IncidentStatus,
        target: IncidentStatus,
        closure_reason: str | None,
        entry: NewTimelineEntry,
        now: datetime,
    ) -> IncidentRecord | None:
        closing = is_closed(target)
        async with self._sessions() as session, session.begin():
            # The expected status is in the WHERE, not in a SELECT the caller made first: two
            # analysts deciding at the same moment is ordinary, and the loser has to be told.
            changed = (
                await session.execute(
                    update(Incident)
                    .where(Incident.id == incident_id, Incident.status == expected)
                    .values(
                        status=target,
                        # ck_incidents_closed_at_matches_status is an equality in both
                        # directions, so these move in the same statement as the status —
                        # and a reopened case stops carrying the reason it was closed for.
                        closed_at=now if closing else None,
                        closure_reason=closure_reason if closing else None,
                        updated_at=now,
                    )
                    .returning(Incident.id)
                )
            ).scalar_one_or_none()
            if changed is None:
                return None
            await self._append_one(session, incident_id, entry, now=now)
            row = (
                await session.execute(select(Incident).where(Incident.id == incident_id))
            ).scalar_one()
            return _incident(row)

    async def add_note(
        self,
        incident_id: UUID,
        *,
        body: str,
        author_id: UUID | None,
        entry: NewTimelineEntry,
        now: datetime,
    ) -> NoteRecord | None:
        async with self._sessions() as session, session.begin():
            present = (
                await session.execute(select(Incident.id).where(Incident.id == incident_id))
            ).scalar_one_or_none()
            if present is None:
                return None
            row = IncidentNote(
                incident_id=incident_id, author_id=author_id, body=body, created_at=now
            )
            session.add(row)
            await session.flush()
            # The timeline says a note exists and how long it is, never what it said: one copy
            # of an analyst's prose, in the table that will not let the app role rewrite it.
            await self._append_one(
                session,
                incident_id,
                replace(entry, detail={**entry.detail, "note_id": str(row.id)}),
                now=now,
            )
            await session.execute(
                update(Incident).where(Incident.id == incident_id).values(updated_at=now)
            )
            await session.refresh(row)
            return _note(row)

    async def list_notes(
        self, incident_id: UUID, *, limit: int, cursor: str | None
    ) -> Page[NoteRecord]:
        statement = select(IncidentNote).where(IncidentNote.incident_id == incident_id)
        if cursor:
            created_at, ident = decode_time_id(cursor)
            statement = statement.where(
                tuple_(IncidentNote.created_at, IncidentNote.id) < (created_at, ident)
            )
        statement = statement.order_by(
            IncidentNote.created_at.desc(), IncidentNote.id.desc()
        ).limit(limit + 1)
        async with self._sessions() as session:
            rows = list((await session.execute(statement)).scalars().all())
        return Page(
            items=tuple(_note(row) for row in rows[:limit]),
            next_cursor=(
                encode_time_id(rows[limit - 1].created_at, rows[limit - 1].id)
                if len(rows) > limit
                else None
            ),
        )

    async def list_timeline(
        self, incident_id: UUID, *, limit: int, cursor: str | None
    ) -> Page[TimelineEntryRecord]:
        statement = select(IncidentTimelineEntry).where(
            IncidentTimelineEntry.incident_id == incident_id
        )
        if cursor:
            occurred_at, ident = decode_time_id(cursor)
            statement = statement.where(
                tuple_(IncidentTimelineEntry.occurred_at, IncidentTimelineEntry.id)
                > (occurred_at, ident)
            )
        statement = statement.order_by(
            IncidentTimelineEntry.occurred_at, IncidentTimelineEntry.id
        ).limit(limit + 1)
        async with self._sessions() as session:
            rows = list((await session.execute(statement)).scalars().all())
        return Page(
            items=tuple(_entry(row) for row in rows[:limit]),
            next_cursor=(
                encode_time_id(rows[limit - 1].occurred_at, rows[limit - 1].id)
                if len(rows) > limit
                else None
            ),
        )

    async def list(self, query: IncidentFilter) -> Page[IncidentRecord]:
        statement = select(Incident)
        if query.status is not None:
            statement = statement.where(Incident.status == query.status)
        if query.open_only:
            statement = statement.where(Incident.status.notin_(_CLOSED))
        if query.severity_min is not None:
            statement = statement.where(Incident.severity >= query.severity_min)
        if query.correlation_key is not None:
            statement = statement.where(Incident.correlation_key == query.correlation_key)
        if query.cursor:
            created_at, ident = decode_time_id(query.cursor)
            statement = statement.where(
                tuple_(Incident.created_at, Incident.id) < (created_at, ident)
            )
        statement = statement.order_by(Incident.created_at.desc(), Incident.id.desc()).limit(
            query.limit + 1
        )
        async with self._sessions() as session:
            rows = list((await session.execute(statement)).scalars().all())
        items = [_incident(row) for row in rows[: query.limit]]
        cursor = (
            encode_time_id(rows[query.limit - 1].created_at, rows[query.limit - 1].id)
            if len(rows) > query.limit
            else None
        )
        return Page(items=tuple(items), next_cursor=cursor)

    async def get(
        self, incident_id: UUID, *, timeline_limit: int = DETAIL_TIMELINE_LIMIT
    ) -> IncidentDetail | None:
        async with self._sessions() as session:
            row = (
                await session.execute(select(Incident).where(Incident.id == incident_id))
            ).scalar_one_or_none()
            return None if row is None else await self._detail(session, row, timeline_limit)

    async def get_by_case_number(
        self, case_number_value: str, *, timeline_limit: int = DETAIL_TIMELINE_LIMIT
    ) -> IncidentDetail | None:
        async with self._sessions() as session:
            row = (
                await session.execute(
                    select(Incident).where(Incident.case_number == case_number_value)
                )
            ).scalar_one_or_none()
            return None if row is None else await self._detail(session, row, timeline_limit)

    # ------------------------------------------------------------------ internals

    async def _detail(
        self, session: AsyncSession, row: Incident, timeline_limit: int
    ) -> IncidentDetail:
        alerts = (
            await session.execute(
                select(Alert, DetectionRule.rule_id)
                .join(IncidentAlert, IncidentAlert.alert_id == Alert.id)
                .join(DetectionRule, DetectionRule.id == Alert.rule_id)
                .where(IncidentAlert.incident_id == row.id)
                .order_by(Alert.first_seen, Alert.id)
            )
        ).all()
        # The newest entries, then turned back into the order things happened. A long case's
        # recent history is the part an analyst needs; the rest is a page away.
        newest = list(
            (
                await session.execute(
                    select(IncidentTimelineEntry)
                    .where(IncidentTimelineEntry.incident_id == row.id)
                    .order_by(
                        IncidentTimelineEntry.occurred_at.desc(), IncidentTimelineEntry.id.desc()
                    )
                    .limit(timeline_limit + 1)
                )
            )
            .scalars()
            .all()
        )
        records: tuple[AlertRecord, ...] = tuple(
            alert_record(alert, rule) for alert, rule in alerts
        )
        return IncidentDetail(
            incident=_incident(row),
            alert_ids=tuple(record.id for record in records),
            timeline=tuple(_entry(entry) for entry in reversed(newest[:timeline_limit])),
            alerts=records,
            timeline_truncated=len(newest) > timeline_limit,
        )

    async def _link(
        self,
        session: AsyncSession,
        incident_id: UUID,
        alert_ids: Sequence[UUID],
        *,
        source: IncidentAlertSource,
        now: datetime,
    ) -> int:
        if not alert_ids:
            return 0
        statement = (
            pg_insert(IncidentAlert)
            .values(
                [
                    {
                        "incident_id": incident_id,
                        "alert_id": alert_id,
                        "added_at": now,
                        "added_by": source,
                    }
                    for alert_id in alert_ids
                ]
            )
            # An alert already in a case stays where it is: one alert, one case.
            .on_conflict_do_nothing(index_elements=["alert_id"])
            .returning(IncidentAlert.alert_id)
        )
        linked = list((await session.execute(statement)).scalars().all())
        if linked:
            await session.execute(
                update(Alert)
                .where(Alert.id.in_(linked), Alert.status == AlertStatus.open)
                .values(status=AlertStatus.correlated)
            )
        return len(linked)

    async def _append(
        self,
        session: AsyncSession,
        incident_id: UUID,
        entries: Sequence[NewTimelineEntry],
        *,
        now: datetime,
    ) -> None:
        if not entries:
            return
        await session.execute(
            pg_insert(IncidentTimelineEntry)
            .values(
                [
                    {
                        "incident_id": incident_id,
                        "occurred_at": entry.occurred_at,
                        "entry_type": entry.entry_type,
                        "summary": entry.summary,
                        "detail": entry.detail,
                        "alert_id": entry.alert_id,
                        "actor_user_id": entry.actor_user_id,
                        "created_at": now,
                    }
                    for entry in entries
                ]
            )
            # A case says the same thing about an alert once, however often correlation runs.
            .on_conflict_do_nothing(
                index_elements=["incident_id", "entry_type", "alert_id"],
            )
        )

    async def _append_one(
        self,
        session: AsyncSession,
        incident_id: UUID,
        entry: NewTimelineEntry,
        *,
        now: datetime,
    ) -> None:
        """One line, inserted plainly.

        Deliberately not ``_append``: that one's ``ON CONFLICT DO NOTHING`` exists so a
        repeated correlation run says the same thing about an alert once. A person changing a
        status twice is saying two things, and both belong in the story.
        """
        session.add(
            IncidentTimelineEntry(
                incident_id=incident_id,
                occurred_at=entry.occurred_at,
                entry_type=entry.entry_type,
                summary=entry.summary,
                detail=entry.detail,
                alert_id=entry.alert_id,
                actor_user_id=entry.actor_user_id,
                created_at=now,
            )
        )
        await session.flush()
