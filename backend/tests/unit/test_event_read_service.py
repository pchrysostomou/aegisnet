"""Event read use-case: the query bounds every caller gets, and pass-through to the store."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from aegisnet.domain.enums import EventType
from aegisnet.domain.pagination import encode_time_id
from aegisnet.domain.ports import EventQuery
from aegisnet.services.event_read_service import (
    EventNotFoundError,
    EventQueryError,
    EventReadService,
)
from tests.fakes import FakeEventStore
from tests.fakes import event_row_stub as _row

pytestmark = pytest.mark.unit

FROM = datetime(2026, 9, 1, tzinfo=UTC)
TO = FROM + timedelta(days=2)


@pytest.fixture
def store() -> FakeEventStore:
    return FakeEventStore()


@pytest.fixture
def service(store: FakeEventStore) -> EventReadService:
    return EventReadService(store)


async def test_a_valid_query_reaches_the_store_unchanged(
    service: EventReadService, store: FakeEventStore
) -> None:
    query = EventQuery(time_from=FROM, time_to=TO, event_types=(EventType.dns,), limit=10)
    await service.query(query)
    assert store.queries == [query]
    stats = await service.stats(query)
    assert stats.total == 0 and store.queries[-1] == query


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"time_from": FROM.replace(tzinfo=None)}, "UTC offset"),
        ({"time_to": FROM}, "after from"),
        ({"time_to": FROM + timedelta(days=31)}, "at most 30 days"),
        ({"limit": 0}, "between 1 and"),
        ({"limit": 201}, "between 1 and"),
        ({"dest_ports": (70000,)}, "dest_port"),
        ({"flow_id": -1}, "flow_id"),
        ({"cursor": "nope"}, "malformed"),
    ],
)
def test_query_bounds_are_enforced(
    service: EventReadService, changes: dict[str, object], message: str
) -> None:
    base = {"time_from": FROM, "time_to": TO}
    with pytest.raises(EventQueryError, match=message):
        service.validate(EventQuery(**{**base, **changes}))  # type: ignore[arg-type]


def test_the_span_is_configurable(store: FakeEventStore) -> None:
    tight = EventReadService(store, max_span=timedelta(hours=1))
    with pytest.raises(EventQueryError, match="at most 0 days"):
        tight.validate(EventQuery(time_from=FROM, time_to=FROM + timedelta(hours=2)))
    tight.validate(EventQuery(time_from=FROM, time_to=FROM + timedelta(hours=1)))


def test_a_well_formed_cursor_passes(service: EventReadService) -> None:
    query = EventQuery(time_from=FROM, time_to=TO, cursor=encode_time_id(FROM, uuid4()))
    assert service.validate(query) is query


async def test_get_honours_the_payload_flag_and_missing_rows(
    service: EventReadService, store: FakeEventStore
) -> None:
    row = _row(payload={"dns": {"rrname": "www.example.test"}})
    store.rows[row.id] = row
    assert (await service.get(row.id, include_payload=True)).payload == row.payload
    assert (await service.get(row.id, include_payload=False)).payload is None
    with pytest.raises(EventNotFoundError):
        await service.get(uuid4(), include_payload=False)
