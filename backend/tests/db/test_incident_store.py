"""The incident tables against PostgreSQL 16 (revision 0004; ADR-023).

What is worth testing here is what the database enforces rather than what Python remembers:
the case-number sequence, the UNIQUE that gives an alert exactly one case, the UNIQUE that
keeps a case from saying the same thing twice, the partial index behind "the open case for
this entity", and the check constraint that ties a closure to its timestamp.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from aegisnet.adapters.db.detection_store import SqlAlertStore, SqlRuleStore
from aegisnet.adapters.db.incident_store import SqlIncidentStore
from aegisnet.adapters.db.session import make_session_factory
from aegisnet.domain.enums import (
    AlertStatus,
    EntityType,
    IncidentStatus,
    TimelineEntryType,
)
from aegisnet.domain.ports import (
    AlertFilter,
    IncidentFilter,
    NewAlert,
    NewIncident,
    NewTimelineEntry,
)

pytestmark = [pytest.mark.db, pytest.mark.integration]

T0 = datetime(2026, 9, 6, 10, 0, tzinfo=UTC)
NOW = datetime(2026, 9, 6, 12, 0, tzinfo=UTC)
HOST = "10.10.0.42"
KEY = f"src_ip={HOST}"


@pytest.fixture(autouse=True)
async def clean_tables(migrator_engine: AsyncEngine) -> AsyncIterator[None]:
    async with migrator_engine.begin() as connection:
        for table in (
            "incident_notes",
            "incident_timeline",
            "incident_alerts",
            "incidents",
            "alerts",
            "detection_rules",
        ):
            await connection.execute(text(f"DELETE FROM {table}"))  # noqa: S608 - fixed names
        await connection.execute(text("ALTER SEQUENCE incident_case_seq RESTART WITH 1"))
    yield


@pytest.fixture
def sessions(app_engine: AsyncEngine):  # type: ignore[no-untyped-def]
    return make_session_factory(app_engine)


@pytest.fixture
def store(sessions) -> SqlIncidentStore:  # type: ignore[no-untyped-def]
    return SqlIncidentStore(sessions)


async def _alerts(sessions, count: int, *, rule: str = "D-001") -> list:  # type: ignore[no-untyped-def]
    """`count` stored alerts to put in cases, through the real alert store."""
    rules = SqlRuleStore(sessions)
    await rules.upsert(
        rule_id=rule,
        name=f"{rule} for the incident tests",
        version=1,
        base_severity=3,
        window_seconds=600,
        params={},
        description="test rule",
        mitre_hint=None,
        now=NOW,
    )
    alerts = SqlAlertStore(sessions)
    await alerts.create_many(
        [
            NewAlert(
                rule_id=rule,
                rule_version=1,
                dedup_key=f"{rule}:{KEY}:{index}",
                severity=3,
                confidence=0.8,
                severity_rationale={"result": 3},
                entity_type=EntityType.src_ip,
                entity_value=HOST,
                first_seen=T0 + timedelta(minutes=index),
                last_seen=T0 + timedelta(minutes=index, seconds=30),
                evidence={},
                event_count=2,
                samples=(),
                assets=(),
            )
            for index in range(count)
        ],
        NOW,
    )
    page = await alerts.list(AlertFilter(limit=100))
    return sorted(page.items, key=lambda a: a.first_seen)


def _new_case(alert_ids: tuple, **overrides) -> NewIncident:  # type: ignore[no-untyped-def]
    values = {
        "correlation_key": KEY,
        "title": f"D-001 on {HOST}",
        "severity": 3,
        "severity_rationale": {"result": 3},
        "window_start": T0,
        "window_end": T0 + timedelta(minutes=10),
        "distinct_rule_count": 1,
        "alert_ids": alert_ids,
    }
    values.update(overrides)
    return NewIncident(**values)  # type: ignore[arg-type]


async def test_opening_a_case_numbers_it_links_its_alerts_and_writes_its_story(
    store: SqlIncidentStore, sessions
) -> None:  # type: ignore[no-untyped-def]
    alerts = await _alerts(sessions, 2)
    record = await store.open_case(
        _new_case(tuple(a.id for a in alerts)),
        [
            NewTimelineEntry(
                occurred_at=a.first_seen,
                entry_type=TimelineEntryType.alert_fired,
                summary=f"{a.rule_id} fired",
                detail={"rule_id": a.rule_id},
                alert_id=a.id,
            )
            for a in alerts
        ],
        now=NOW,
    )

    assert record.case_number == "AEG-2026-0001"
    assert record.status is IncidentStatus.new
    detail = await store.get(record.id)
    assert detail is not None
    assert set(detail.alert_ids) == {a.id for a in alerts}
    assert [e.entry_type for e in detail.timeline] == [TimelineEntryType.alert_fired] * 2
    assert [e.occurred_at for e in detail.timeline] == sorted(
        e.occurred_at for e in detail.timeline
    )

    # The alerts are no longer waiting to be correlated.
    stored = await SqlAlertStore(sessions).list(AlertFilter(limit=10))
    assert {a.status for a in stored.items} == {AlertStatus.correlated}


async def test_case_numbers_come_from_a_sequence_and_do_not_repeat(
    store: SqlIncidentStore, sessions
) -> None:  # type: ignore[no-untyped-def]
    alerts = await _alerts(sessions, 3)
    numbers = [
        (await store.open_case(_new_case((alert.id,)), [], now=NOW)).case_number for alert in alerts
    ]
    assert numbers == ["AEG-2026-0001", "AEG-2026-0002", "AEG-2026-0003"]


async def test_an_alert_belongs_to_exactly_one_case(store: SqlIncidentStore, sessions) -> None:  # type: ignore[no-untyped-def]
    """The UNIQUE on `alert_id` is what makes a re-run a no-op rather than a second opinion."""
    [alert] = await _alerts(sessions, 1)
    first = await store.open_case(_new_case((alert.id,)), [], now=NOW)
    second = await store.open_case(_new_case((alert.id,)), [], now=NOW)

    assert await store.already_linked([alert.id]) == {alert.id}
    first_detail = await store.get(first.id)
    second_detail = await store.get(second.id)
    assert first_detail is not None and second_detail is not None
    assert first_detail.alert_ids == (alert.id,)
    assert second_detail.alert_ids == (), "the second case did not steal it"


async def test_extending_a_case_grows_its_window_and_never_shrinks_it(
    store: SqlIncidentStore, sessions
) -> None:  # type: ignore[no-untyped-def]
    alerts = await _alerts(sessions, 3)
    case = await store.open_case(_new_case((alerts[0].id,)), [], now=NOW)

    linked = await store.extend(
        case.id,
        [alerts[1].id],
        [],
        severity=4,
        severity_rationale={"result": 4},
        title="two rules",
        window_end=T0 + timedelta(hours=2),
        distinct_rule_count=2,
        now=NOW,
    )
    assert linked == 1

    # An older window end must not pull the case backwards.
    await store.extend(
        case.id,
        [alerts[2].id],
        [],
        severity=4,
        severity_rationale={"result": 4},
        title="two rules",
        window_end=T0 - timedelta(hours=1),
        distinct_rule_count=2,
        now=NOW,
    )
    detail = await store.get(case.id)
    assert detail is not None
    assert detail.incident.window_end == T0 + timedelta(hours=2)
    assert detail.incident.severity == 4
    assert len(detail.alert_ids) == 3


async def test_a_case_says_the_same_thing_about_an_alert_once(
    store: SqlIncidentStore, sessions
) -> None:  # type: ignore[no-untyped-def]
    [alert] = await _alerts(sessions, 1)
    entry = NewTimelineEntry(
        occurred_at=alert.first_seen,
        entry_type=TimelineEntryType.alert_fired,
        summary="D-001 fired",
        alert_id=alert.id,
    )
    case = await store.open_case(_new_case((alert.id,)), [entry], now=NOW)
    await store.extend(
        case.id,
        [alert.id],
        [entry],
        severity=3,
        severity_rationale={"result": 3},
        title="same",
        window_end=T0,
        distinct_rule_count=1,
        now=NOW,
    )
    detail = await store.get(case.id)
    assert detail is not None
    assert len(detail.timeline) == 1


async def test_the_open_case_for_an_entity_ignores_closed_ones(
    store: SqlIncidentStore, sessions, migrator_engine: AsyncEngine
) -> None:  # type: ignore[no-untyped-def]
    alerts = await _alerts(sessions, 2)
    closed = await store.open_case(_new_case((alerts[0].id,)), [], now=NOW)
    async with migrator_engine.begin() as connection:
        await connection.execute(
            text("UPDATE incidents SET status = 'closed_benign', closed_at = now() WHERE id = :id"),
            {"id": closed.id},
        )

    assert await store.newest_open_for_key(KEY) is None
    predecessor = await store.newest_closed_for_key(KEY)
    assert predecessor is not None and predecessor.id == closed.id

    fresh = await store.open_case(_new_case((alerts[1].id,)), [], now=NOW)
    newest = await store.newest_open_for_key(KEY)
    assert newest is not None and newest.id == fresh.id


async def test_a_closure_without_its_timestamp_is_refused_by_the_database(
    store: SqlIncidentStore, sessions, migrator_engine: AsyncEngine
) -> None:  # type: ignore[no-untyped-def]
    """A closed case carries the moment it closed, and an open one does not pretend to."""
    [alert] = await _alerts(sessions, 1)
    case = await store.open_case(_new_case((alert.id,)), [], now=NOW)
    with pytest.raises(Exception, match="ck_incidents_closed_at_matches_status"):
        async with migrator_engine.begin() as connection:
            await connection.execute(
                text("UPDATE incidents SET status = 'closed_true_positive' WHERE id = :id"),
                {"id": case.id},
            )


async def test_listing_filters_by_status_severity_and_key(
    store: SqlIncidentStore, sessions, migrator_engine: AsyncEngine
) -> None:  # type: ignore[no-untyped-def]
    alerts = await _alerts(sessions, 3)
    low = await store.open_case(_new_case((alerts[0].id,), severity=2), [], now=NOW)
    high = await store.open_case(_new_case((alerts[1].id,), severity=5), [], now=NOW)
    other = await store.open_case(
        _new_case((alerts[2].id,), correlation_key="src_ip=10.10.0.9"), [], now=NOW
    )
    async with migrator_engine.begin() as connection:
        await connection.execute(
            text("UPDATE incidents SET status = 'closed_benign', closed_at = now() WHERE id = :id"),
            {"id": low.id},
        )

    everything = await store.list(IncidentFilter(limit=10))
    assert {row.id for row in everything.items} == {low.id, high.id, other.id}
    open_only = await store.list(IncidentFilter(open_only=True, limit=10))
    assert {row.id for row in open_only.items} == {high.id, other.id}
    severe = await store.list(IncidentFilter(severity_min=5, limit=10))
    assert {row.id for row in severe.items} == {high.id}
    by_key = await store.list(IncidentFilter(correlation_key=KEY, limit=10))
    assert {row.id for row in by_key.items} == {low.id, high.id}


async def test_a_case_can_be_found_by_its_number(store: SqlIncidentStore, sessions) -> None:  # type: ignore[no-untyped-def]
    [alert] = await _alerts(sessions, 1)
    case = await store.open_case(_new_case((alert.id,)), [], now=NOW)
    detail = await store.get_by_case_number(case.case_number)
    assert detail is not None and detail.incident.id == case.id
    assert await store.get_by_case_number("AEG-2026-9999") is None
    assert await store.get(uuid4()) is None
