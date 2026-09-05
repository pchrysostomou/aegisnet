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
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import func, select, text, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from aegisnet.adapters.db.models import (
    Alert,
    Incident,
    IncidentAlert,
    IncidentTimelineEntry,
)
from aegisnet.domain.enums import AlertStatus, IncidentAlertSource, IncidentStatus
from aegisnet.domain.incidents import CLOSED_STATUSES, case_number
from aegisnet.domain.pagination import decode_time_id, encode_time_id
from aegisnet.domain.ports import (
    IncidentDetail,
    IncidentFilter,
    IncidentRecord,
    NewIncident,
    NewTimelineEntry,
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
                (Incident.created_at, Incident.id) < (created_at, ident)  # type: ignore[operator]
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

    async def get(self, incident_id: UUID) -> IncidentDetail | None:
        async with self._sessions() as session:
            row = (
                await session.execute(select(Incident).where(Incident.id == incident_id))
            ).scalar_one_or_none()
            return None if row is None else await self._detail(session, row)

    async def get_by_case_number(self, case_number_value: str) -> IncidentDetail | None:
        async with self._sessions() as session:
            row = (
                await session.execute(
                    select(Incident).where(Incident.case_number == case_number_value)
                )
            ).scalar_one_or_none()
            return None if row is None else await self._detail(session, row)

    # ------------------------------------------------------------------ internals

    async def _detail(self, session: AsyncSession, row: Incident) -> IncidentDetail:
        alerts = (
            await session.execute(
                select(IncidentAlert.alert_id)
                .join(Alert, Alert.id == IncidentAlert.alert_id)
                .where(IncidentAlert.incident_id == row.id)
                .order_by(Alert.first_seen, Alert.id)
            )
        ).scalars()
        timeline = (
            await session.execute(
                select(IncidentTimelineEntry)
                .where(IncidentTimelineEntry.incident_id == row.id)
                .order_by(IncidentTimelineEntry.occurred_at, IncidentTimelineEntry.created_at)
            )
        ).scalars()
        return IncidentDetail(
            incident=_incident(row),
            alert_ids=tuple(alerts.all()),
            timeline=tuple(_entry(entry) for entry in timeline.all()),
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
