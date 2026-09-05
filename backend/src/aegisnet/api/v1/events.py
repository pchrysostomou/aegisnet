"""Read-only event routes. The payload is included only for principals holding
``events.payload`` (analyst and above); viewers receive the promoted columns only."""

from __future__ import annotations

import time
from datetime import datetime
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Response

from aegisnet.api.deps import AppServices, rate_limit, require, services
from aegisnet.api.schemas import EventOut, EventPage, StatsOut
from aegisnet.domain.auth import Permission, Principal
from aegisnet.domain.enums import EventType
from aegisnet.domain.pagination import DEFAULT_LIMIT, MAX_LIMIT
from aegisnet.domain.ports import EventQuery

router = APIRouter(prefix="/api/v1/events", tags=["events"])

IPOrNetwork = IPv4Address | IPv6Address | IPv4Network | IPv6Network


def _query(
    time_from: datetime,
    time_to: datetime,
    event_type: list[EventType],
    src_ip: IPOrNetwork | None,
    dest_ip: IPOrNetwork | None,
    dest_port: list[int],
    flow_id: int | None,
    batch_id: UUID | None,
    asset_id: UUID | None,
    limit: int,
    cursor: str | None,
    include_payload: bool,
) -> EventQuery:
    return EventQuery(
        time_from=time_from,
        time_to=time_to,
        event_types=tuple(event_type),
        src_ip=src_ip,
        dest_ip=dest_ip,
        dest_ports=tuple(dest_port),
        flow_id=flow_id,
        batch_id=batch_id,
        asset_id=asset_id,
        limit=limit,
        cursor=cursor,
        include_payload=include_payload,
    )


@router.get(
    "",
    response_model=EventPage,
    summary="Events in a window, newest first, keyset-paginated",
    dependencies=[Depends(rate_limit("read"))],
)
async def list_events(
    response: Response,
    svc: Annotated[AppServices, Depends(services)],
    principal: Annotated[Principal, Depends(require(Permission.events_read))],
    time_from: Annotated[datetime, Query(alias="from")],
    time_to: Annotated[datetime, Query(alias="to")],
    event_type: Annotated[list[EventType], Query()] = [],  # noqa: B006 - FastAPI query default
    src_ip: IPOrNetwork | None = None,
    dest_ip: IPOrNetwork | None = None,
    dest_port: Annotated[list[int], Query()] = [],  # noqa: B006 - FastAPI query default
    flow_id: Annotated[int | None, Query(ge=0)] = None,
    batch_id: UUID | None = None,
    asset_id: UUID | None = None,
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = DEFAULT_LIMIT,
    cursor: str | None = None,
) -> EventPage:
    started = time.perf_counter()
    page = await svc.events.query(
        _query(
            time_from,
            time_to,
            event_type,
            src_ip,
            dest_ip,
            dest_port,
            flow_id,
            batch_id,
            asset_id,
            limit,
            cursor,
            principal.can(Permission.events_payload),
        )
    )
    response.headers["X-Query-Duration-ms"] = str(int((time.perf_counter() - started) * 1000))
    return EventPage(items=[EventOut.from_row(r) for r in page.items], next_cursor=page.next_cursor)


@router.get(
    "/stats",
    response_model=StatsOut,
    summary="Counts by type and by hour over a window",
    dependencies=[Depends(require(Permission.events_read)), Depends(rate_limit("read"))],
)
async def event_stats(
    svc: Annotated[AppServices, Depends(services)],
    time_from: Annotated[datetime, Query(alias="from")],
    time_to: Annotated[datetime, Query(alias="to")],
    event_type: Annotated[list[EventType], Query()] = [],  # noqa: B006 - FastAPI query default
    asset_id: UUID | None = None,
) -> StatsOut:
    stats = await svc.events.stats(
        _query(time_from, time_to, event_type, None, None, [], None, None, asset_id, 1, None, False)
    )
    return StatsOut.from_stats(stats)


@router.get(
    "/{event_id}",
    response_model=EventOut,
    summary="One event with its full validated payload",
    dependencies=[Depends(require(Permission.events_payload)), Depends(rate_limit("read"))],
)
async def get_event(event_id: UUID, svc: Annotated[AppServices, Depends(services)]) -> EventOut:
    return EventOut.from_row(await svc.events.get(event_id, include_payload=True))
