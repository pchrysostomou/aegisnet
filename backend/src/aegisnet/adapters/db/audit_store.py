"""Append-only audit log: the runtime role holds INSERT and SELECT here, nothing else
(ADR-012). Each write is its own transaction so a rolled-back request keeps its trail."""

from __future__ import annotations

from ipaddress import ip_address

from sqlalchemy import insert, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from aegisnet.adapters.db.models import AuditLog
from aegisnet.domain.enums import AuditResult
from aegisnet.domain.pagination import decode_int, encode_int
from aegisnet.domain.ports import AuditEntry, AuditFilter, AuditRow, Page


def _row(row: AuditLog) -> AuditRow:
    return AuditRow(
        id=row.id,
        entry=AuditEntry(
            occurred_at=row.occurred_at,
            action=row.action,
            target_type=row.target_type,
            target_id=row.target_id,
            result=AuditResult(row.result),
            detail=dict(row.detail),
            actor_user_id=row.actor_user_id,
            actor_token_id=row.actor_token_id,
            actor_ip=None if row.actor_ip is None else ip_address(str(row.actor_ip).split("/")[0]),
            correlation_id=row.correlation_id,
        ),
    )


class SqlAuditStore:
    """Both the sink and the read side, over one session factory."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._sessions = session_factory

    async def write(self, entry: AuditEntry) -> None:
        async with self._sessions() as session, session.begin():
            await session.execute(
                insert(AuditLog).values(
                    occurred_at=entry.occurred_at,
                    actor_user_id=entry.actor_user_id,
                    actor_token_id=entry.actor_token_id,
                    actor_ip=None if entry.actor_ip is None else str(entry.actor_ip),
                    action=entry.action,
                    target_type=entry.target_type,
                    target_id=entry.target_id,
                    result=entry.result,
                    detail=entry.detail,
                    correlation_id=entry.correlation_id,
                )
            )

    async def list(self, query: AuditFilter) -> Page[AuditRow]:
        statement = select(AuditLog)
        if query.action is not None:
            statement = statement.where(AuditLog.action == query.action)
        if query.actor_user_id is not None:
            statement = statement.where(AuditLog.actor_user_id == query.actor_user_id)
        if query.result is not None:
            statement = statement.where(AuditLog.result == query.result)
        if query.time_from is not None:
            statement = statement.where(AuditLog.occurred_at >= query.time_from)
        if query.time_to is not None:
            statement = statement.where(AuditLog.occurred_at <= query.time_to)
        if query.cursor is not None:
            statement = statement.where(AuditLog.id < decode_int(query.cursor))
        statement = statement.order_by(AuditLog.id.desc()).limit(query.limit + 1)
        async with self._sessions() as session:
            rows = list((await session.execute(statement)).scalars())
        has_more = len(rows) > query.limit
        rows = rows[: query.limit]
        next_cursor = encode_int(rows[-1].id) if has_more else None
        return Page(items=tuple(_row(row) for row in rows), next_cursor=next_cursor)
