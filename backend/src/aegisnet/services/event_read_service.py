"""Read-only event queries (M1 API: ``GET /events``, ``/events/{id}``, ``/events/stats``).

Validation lives here so every caller (the CLI now, the routes in Chunk 6) gets the same
bounds: an explicit, timezone-aware window no wider than ``max_span`` (T-2.6), a page
size of at most 200, and a cursor that decodes. ``include_payload`` is the caller's
decision; the routes will set it from the role (``viewer`` never sees payloads).
"""

from __future__ import annotations

from datetime import timedelta
from typing import Final
from uuid import UUID

from aegisnet.domain.pagination import InvalidCursorError, check_limit, decode_time_id
from aegisnet.domain.ports import EventQuery, EventReadStore, EventRow, EventStats, Page

DEFAULT_MAX_SPAN: Final = timedelta(days=30)


class EventQueryError(ValueError):
    pass


class EventNotFoundError(Exception):
    pass


class EventReadService:
    def __init__(self, store: EventReadStore, *, max_span: timedelta = DEFAULT_MAX_SPAN) -> None:
        self._store = store
        self._max_span = max_span

    def validate(self, query: EventQuery) -> EventQuery:
        if query.time_from.tzinfo is None or query.time_to.tzinfo is None:
            raise EventQueryError("from and to must carry a UTC offset")
        if query.time_to <= query.time_from:
            raise EventQueryError("to must be after from")
        if query.time_to - query.time_from > self._max_span:
            days = self._max_span.days
            raise EventQueryError(f"the window may span at most {days} days")
        try:
            check_limit(query.limit)
        except ValueError as error:
            raise EventQueryError(str(error)) from error
        if any(not 0 <= port <= 65535 for port in query.dest_ports):
            raise EventQueryError("dest_port must be between 0 and 65535")
        if query.flow_id is not None and query.flow_id < 0:
            raise EventQueryError("flow_id must not be negative")
        if query.cursor is not None:
            try:
                decode_time_id(query.cursor)
            except InvalidCursorError as error:
                raise EventQueryError(str(error)) from error
        return query

    async def query(self, query: EventQuery) -> Page[EventRow]:
        return await self._store.query(self.validate(query))

    async def get(self, event_id: UUID, *, include_payload: bool) -> EventRow:
        row = await self._store.get(event_id, include_payload=include_payload)
        if row is None:
            raise EventNotFoundError("unknown event")
        return row

    async def stats(self, query: EventQuery) -> EventStats:
        return await self._store.stats(self.validate(query))
