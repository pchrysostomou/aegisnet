"""T-2.6: every list is bounded — page size, time span, and opaque cursors that refuse
tampering — at the service layer, so no route can forget it."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from aegisnet.domain.pagination import MAX_LIMIT, InvalidCursorError, encode_int, encode_time_id
from aegisnet.domain.ports import AssetFilter, BatchFilter, EventQuery
from aegisnet.services.asset_service import AssetService
from aegisnet.services.event_read_service import EventQueryError, EventReadService
from aegisnet.services.ingest_service import BatchNotFoundError, IngestService, limits_from_settings
from tests.conftest import make_settings
from tests.fakes import FakeAssetStore, FakeEventStore
from tests.fakes import FakeIngestStore as FakeStore

pytestmark = pytest.mark.security

FROM = datetime(2026, 9, 1, tzinfo=UTC)


@pytest.fixture
def ingest() -> IngestService:
    return IngestService(FakeStore(), limits_from_settings(make_settings()))


@pytest.fixture
def assets() -> AssetService:
    return AssetService(FakeAssetStore())


@pytest.fixture
def events() -> EventReadService:
    return EventReadService(FakeEventStore())


@pytest.mark.parametrize("limit", [0, MAX_LIMIT + 1, 10_000])
async def test_page_sizes_are_capped_everywhere(
    ingest: IngestService, assets: AssetService, events: EventReadService, limit: int
) -> None:
    with pytest.raises(ValueError, match="between 1 and"):
        await ingest.list_batches(BatchFilter(limit=limit))
    with pytest.raises(ValueError, match="between 1 and"):
        await ingest.list_rejects(uuid4(), limit=limit)
    with pytest.raises(ValueError, match="between 1 and"):
        await assets.list(AssetFilter(limit=limit))
    with pytest.raises(EventQueryError, match="between 1 and"):
        await events.query(
            EventQuery(time_from=FROM, time_to=FROM + timedelta(days=1), limit=limit)
        )


@pytest.mark.parametrize("cursor", ["", "junk", "eyJvZmZzZXQiOiAxMDAwMDAwfQ", "x" * 5000])
async def test_tampered_cursors_are_refused_everywhere(
    ingest: IngestService, assets: AssetService, events: EventReadService, cursor: str
) -> None:
    with pytest.raises(InvalidCursorError):
        await ingest.list_batches(BatchFilter(cursor=cursor))
    with pytest.raises(InvalidCursorError):
        await ingest.list_rejects(uuid4(), cursor=cursor)
    with pytest.raises(InvalidCursorError):
        await assets.list(AssetFilter(cursor=cursor))
    with pytest.raises(EventQueryError, match="malformed"):
        await events.query(
            EventQuery(time_from=FROM, time_to=FROM + timedelta(days=1), cursor=cursor)
        )


async def test_a_cursor_for_one_list_does_not_open_another(ingest: IngestService) -> None:
    time_cursor = encode_time_id(FROM, uuid4())
    with pytest.raises(InvalidCursorError):
        await ingest.list_rejects(uuid4(), cursor=time_cursor)
    with pytest.raises(InvalidCursorError):
        await ingest.list_batches(BatchFilter(cursor=encode_int(7)))


async def test_rejects_of_an_unknown_batch_are_not_enumerable(ingest: IngestService) -> None:
    with pytest.raises(BatchNotFoundError):
        await ingest.list_rejects(uuid4())


async def test_event_windows_are_explicit_and_bounded(events: EventReadService) -> None:
    with pytest.raises(EventQueryError, match="at most 30 days"):
        await events.query(EventQuery(time_from=FROM, time_to=FROM + timedelta(days=31)))
    with pytest.raises(EventQueryError, match="UTC offset"):
        await events.query(EventQuery(time_from=FROM.replace(tzinfo=None), time_to=FROM))
    with pytest.raises(EventQueryError, match="after from"):
        await events.stats(EventQuery(time_from=FROM, time_to=FROM))
