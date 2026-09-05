"""SQLAlchemy implementation of :class:`aegisnet.domain.ports.EventReadStore`.

Keyset pagination on ``(event_time DESC, id DESC)`` backed by ``ix_events_event_time``;
the payload column is selected only when asked for, so a viewer-level query never even
reads it. The asset filter uses the asset's own networks with the inet containment
operator, which the GiST index on ``asset_networks.cidr`` serves.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from ipaddress import IPv4Network, IPv6Network, ip_address
from typing import Any
from uuid import UUID

from sqlalchemy import Row, Select, cast, exists, func, or_, select, tuple_
from sqlalchemy.dialects.postgresql import CIDR, INET
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from aegisnet.adapters.db.models import AssetNetwork, Event
from aegisnet.domain.assets import IPAddress, IPNetwork
from aegisnet.domain.detectors.addresses import INTERNAL_NETWORKS
from aegisnet.domain.enums import EventType
from aegisnet.domain.pagination import decode_time_id, encode_time_id
from aegisnet.domain.ports import EventQuery, EventReadStore, EventRow, EventStats, Page

COLUMNS = (
    Event.id,
    Event.batch_id,
    Event.event_time,
    Event.ingested_at,
    Event.event_type,
    Event.flow_id,
    Event.src_ip,
    Event.dest_ip,
    Event.src_port,
    Event.dest_port,
    Event.proto,
    Event.app_proto,
    Event.bytes_toserver,
    Event.bytes_toclient,
    Event.pkts_toserver,
    Event.pkts_toclient,
    Event.dns_query,
    Event.dns_rrtype,
    Event.dns_rcode,
    Event.http_host,
    Event.http_url_path,
    Event.sig_signature,
    Event.sig_category,
    Event.sig_signature_id,
    Event.sig_severity,
)


def _address(value: object) -> IPAddress | None:
    if value is None:
        return None
    text = str(value)
    return ip_address(text.split("/")[0]) if "/" in text else ip_address(text)


def _row(row: Row[Any], payload: dict[str, Any] | None) -> EventRow:
    return EventRow(
        id=row.id,
        batch_id=row.batch_id,
        event_time=row.event_time,
        ingested_at=row.ingested_at,
        event_type=EventType(row.event_type),
        flow_id=row.flow_id,
        src_ip=_address(row.src_ip),
        dest_ip=_address(row.dest_ip),
        src_port=row.src_port,
        dest_port=row.dest_port,
        proto=row.proto,
        app_proto=row.app_proto,
        bytes_toserver=row.bytes_toserver,
        bytes_toclient=row.bytes_toclient,
        pkts_toserver=row.pkts_toserver,
        pkts_toclient=row.pkts_toclient,
        dns_query=row.dns_query,
        dns_rrtype=row.dns_rrtype,
        dns_rcode=row.dns_rcode,
        http_host=row.http_host,
        http_url_path=row.http_url_path,
        sig_signature=row.sig_signature,
        sig_category=row.sig_category,
        sig_signature_id=row.sig_signature_id,
        sig_severity=row.sig_severity,
        payload=payload,
    )


def _ip_clause(column: Any, value: IPAddress | IPNetwork) -> Any:
    if isinstance(value, IPv4Network | IPv6Network):
        return column.op("<<=")(cast(str(value), CIDR))
    return column == cast(str(value), INET)


def _apply_filters(statement: Select[Any], query: EventQuery) -> Select[Any]:
    statement = statement.where(
        Event.event_time >= query.time_from, Event.event_time <= query.time_to
    )
    if query.event_types:
        statement = statement.where(Event.event_type.in_(query.event_types))
    if query.src_ip is not None:
        statement = statement.where(_ip_clause(Event.src_ip, query.src_ip))
    if query.dest_ip is not None:
        statement = statement.where(_ip_clause(Event.dest_ip, query.dest_ip))
    if query.dest_ports:
        statement = statement.where(Event.dest_port.in_(query.dest_ports))
    if query.flow_id is not None:
        statement = statement.where(Event.flow_id == query.flow_id)
    if query.batch_id is not None:
        statement = statement.where(Event.batch_id == query.batch_id)
    if query.asset_id is not None:
        member = exists(
            select(AssetNetwork.id).where(
                AssetNetwork.asset_id == query.asset_id,
                or_(
                    Event.src_ip.op("<<=")(AssetNetwork.cidr),
                    Event.dest_ip.op("<<=")(AssetNetwork.cidr),
                ),
            )
        )
        statement = statement.where(member)
    return statement


class SqlEventReadStore(EventReadStore):
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._sessions = session_factory

    async def query(self, query: EventQuery) -> Page[EventRow]:
        columns: Sequence[Any] = (*COLUMNS, Event.payload) if query.include_payload else COLUMNS
        statement = _apply_filters(select(*columns), query)
        if query.cursor is not None:
            moment, last_id = decode_time_id(query.cursor)
            statement = statement.where(tuple_(Event.event_time, Event.id) < (moment, last_id))
        statement = statement.order_by(Event.event_time.desc(), Event.id.desc()).limit(
            query.limit + 1
        )
        async with self._sessions() as session:
            rows = (await session.execute(statement)).all()
        has_more = len(rows) > query.limit
        rows = rows[: query.limit]
        items = tuple(_row(row, row.payload if query.include_payload else None) for row in rows)
        next_cursor = (
            encode_time_id(rows[-1].event_time, rows[-1].id) if has_more and rows else None
        )
        return Page(items=items, next_cursor=next_cursor)

    async def load(
        self, start: datetime, end: datetime, *, max_events: int
    ) -> tuple[tuple[EventRow, ...], bool]:
        """The window loader for the detection sweep (``EventWindowStore``): oldest first,
        payload never read, one row past the cap to learn whether the cap was hit."""
        statement = (
            select(*COLUMNS)
            .where(Event.event_time >= start, Event.event_time < end)
            .order_by(Event.event_time.asc(), Event.id.asc())
            .limit(max_events + 1)
        )
        async with self._sessions() as session:
            rows = (await session.execute(statement)).all()
        truncated = len(rows) > max_events
        return tuple(_row(row, None) for row in rows[:max_events]), truncated

    async def hourly_outbound_bytes(
        self, networks: Sequence[IPNetwork], start: datetime, end: datetime
    ) -> tuple[tuple[datetime, int], ...]:
        """The history D-005's baselines are built from (``OutboundHistoryStore``)."""
        if not networks:
            return ()
        hour = func.date_trunc("hour", Event.event_time).label("hour")
        internal = or_(*[Event.dest_ip.op("<<=")(cast(str(n), CIDR)) for n in INTERNAL_NETWORKS])
        inside = or_(*[Event.src_ip.op("<<=")(cast(str(n), CIDR)) for n in networks])
        statement = (
            select(hour, func.coalesce(func.sum(Event.bytes_toserver), 0))
            .where(
                Event.event_type == EventType.flow,
                Event.event_time >= start,
                Event.event_time < end,
                Event.bytes_toserver.is_not(None),
                Event.dest_ip.is_not(None),
                inside,
                ~internal,
            )
            .group_by(hour)
            .order_by(hour)
        )
        async with self._sessions() as session:
            rows = (await session.execute(statement)).all()
        return tuple((moment, int(total)) for moment, total in rows)

    async def get(self, event_id: UUID, *, include_payload: bool) -> EventRow | None:
        columns: Sequence[Any] = (*COLUMNS, Event.payload) if include_payload else COLUMNS
        async with self._sessions() as session:
            row = (
                await session.execute(select(*columns).where(Event.id == event_id))
            ).one_or_none()
        if row is None:
            return None
        return _row(row, row.payload if include_payload else None)

    async def stats(self, query: EventQuery) -> EventStats:
        by_type = _apply_filters(
            select(Event.event_type, func.count()).group_by(Event.event_type), query
        ).order_by(Event.event_type)
        hour = func.date_trunc("hour", Event.event_time)
        by_hour = _apply_filters(select(hour, func.count()).group_by(hour), query).order_by(hour)
        async with self._sessions() as session:
            type_rows = (await session.execute(by_type)).all()
            hour_rows = (await session.execute(by_hour)).all()
        types = tuple((EventType(kind).value, int(count)) for kind, count in type_rows)
        hours: tuple[tuple[datetime, int], ...] = tuple(
            (moment, int(count)) for moment, count in hour_rows
        )
        return EventStats(total=sum(count for _, count in types), by_type=types, by_hour=hours)
