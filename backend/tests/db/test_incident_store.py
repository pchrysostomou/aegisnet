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


# ---------------------------------------------------------------- the workflow (Chunk 16)


async def _open_one(store: SqlIncidentStore, sessions, *, count: int = 1):  # type: ignore[no-untyped-def]
    alerts = await _alerts(sessions, count)
    record = await store.open_case(
        _new_case(tuple(a.id for a in alerts)),
        [
            NewTimelineEntry(
                occurred_at=a.first_seen,
                entry_type=TimelineEntryType.alert_fired,
                summary=f"{a.rule_id} fired",
                alert_id=a.id,
            )
            for a in alerts
        ],
        now=NOW,
    )
    return record, alerts


def _change(target: IncidentStatus, at: datetime) -> NewTimelineEntry:
    return NewTimelineEntry(
        occurred_at=at,
        entry_type=TimelineEntryType.status_change,
        summary=f"Status changed to {target.value}",
        detail={"to": target.value},
    )


async def test_a_status_change_moves_the_case_and_writes_one_line(
    store: SqlIncidentStore, sessions
) -> None:  # type: ignore[no-untyped-def]
    record, _alerts_ = await _open_one(store, sessions)
    moved = await store.set_status(
        record.id,
        expected=IncidentStatus.new,
        target=IncidentStatus.triaging,
        closure_reason=None,
        entry=_change(IncidentStatus.triaging, NOW),
        now=NOW,
    )
    assert moved is not None
    assert moved.status is IncidentStatus.triaging
    assert moved.closed_at is None and moved.closure_reason is None
    detail = await store.get(record.id)
    assert detail is not None
    assert [e.entry_type for e in detail.timeline] == [
        TimelineEntryType.alert_fired,
        TimelineEntryType.status_change,
    ]


async def test_a_change_from_a_status_the_case_no_longer_holds_writes_nothing(
    store: SqlIncidentStore, sessions
) -> None:  # type: ignore[no-untyped-def]
    record, _alerts_ = await _open_one(store, sessions)
    await store.set_status(
        record.id,
        expected=IncidentStatus.new,
        target=IncidentStatus.triaging,
        closure_reason=None,
        entry=_change(IncidentStatus.triaging, NOW),
        now=NOW,
    )
    # The second caller still believes the case is `new`: it must lose, and leave no trace.
    lost = await store.set_status(
        record.id,
        expected=IncidentStatus.new,
        target=IncidentStatus.investigating,
        closure_reason=None,
        entry=_change(IncidentStatus.investigating, NOW),
        now=NOW,
    )
    assert lost is None
    detail = await store.get(record.id)
    assert detail is not None
    assert detail.incident.status is IncidentStatus.triaging
    assert sum(1 for e in detail.timeline if e.entry_type is TimelineEntryType.status_change) == 1


async def test_closing_and_reopening_satisfy_the_check_constraint_in_both_directions(
    store: SqlIncidentStore, sessions
) -> None:  # type: ignore[no-untyped-def]
    record, _alerts_ = await _open_one(store, sessions)
    closed = await store.set_status(
        record.id,
        expected=IncidentStatus.new,
        target=IncidentStatus.closed_benign,
        closure_reason="a known backup job",
        entry=_change(IncidentStatus.closed_benign, NOW),
        now=NOW,
    )
    assert closed is not None
    assert closed.closed_at == NOW
    assert closed.closure_reason == "a known backup job"
    # ck_incidents_closed_at_matches_status is an equality, so reopening has to clear both or
    # the statement fails outright rather than leaving a case that claims to be closed.
    later = NOW + timedelta(hours=1)
    reopened = await store.set_status(
        record.id,
        expected=IncidentStatus.closed_benign,
        target=IncidentStatus.investigating,
        closure_reason=None,
        entry=_change(IncidentStatus.investigating, later),
        now=later,
    )
    assert reopened is not None
    assert reopened.closed_at is None and reopened.closure_reason is None


async def test_a_case_takes_many_status_changes_because_nulls_are_distinct(
    store: SqlIncidentStore, sessions
) -> None:  # type: ignore[no-untyped-def]
    """uq_incident_timeline_alert_entry is (incident_id, entry_type, alert_id). A status
    change carries no alert, and PostgreSQL counts NULLs as distinct, so the constraint never
    collapses a case's history into one line. This is the test that says so out loud."""
    record, _alerts_ = await _open_one(store, sessions)
    walk = [
        (IncidentStatus.new, IncidentStatus.triaging),
        (IncidentStatus.triaging, IncidentStatus.investigating),
        (IncidentStatus.investigating, IncidentStatus.contained_recommended),
    ]
    for index, (current, target) in enumerate(walk):
        assert (
            await store.set_status(
                record.id,
                expected=current,
                target=target,
                closure_reason=None,
                entry=_change(target, NOW + timedelta(minutes=index)),
                now=NOW + timedelta(minutes=index),
            )
            is not None
        )
    detail = await store.get(record.id)
    assert detail is not None
    changes = [e for e in detail.timeline if e.entry_type is TimelineEntryType.status_change]
    assert [e.detail["to"] for e in changes] == [
        "triaging",
        "investigating",
        "contained_recommended",
    ]


async def test_correlation_still_says_the_same_thing_about_an_alert_once(
    store: SqlIncidentStore, sessions
) -> None:  # type: ignore[no-untyped-def]
    """The non-regression for splitting `_append_one` out of `_append`: the ON CONFLICT that
    makes a re-run a no-op has to still be on the path correlation uses."""
    record, alerts = await _open_one(store, sessions, count=1)
    repeat = NewTimelineEntry(
        occurred_at=alerts[0].first_seen,
        entry_type=TimelineEntryType.alert_fired,
        summary="D-001 fired (again)",
        alert_id=alerts[0].id,
    )
    linked = await store.extend(
        record.id,
        [alerts[0].id],
        [repeat],
        severity=3,
        severity_rationale={"result": 3},
        title=record.title,
        window_end=record.window_end,
        distinct_rule_count=1,
        now=NOW,
    )
    assert linked == 0
    detail = await store.get(record.id)
    assert detail is not None
    assert [e.entry_type for e in detail.timeline] == [TimelineEntryType.alert_fired]


# ---------------------------------------------------------------- notes and reads


async def test_a_note_is_stored_with_its_timeline_line_and_pages_newest_first(
    store: SqlIncidentStore, sessions
) -> None:  # type: ignore[no-untyped-def]
    record, _alerts_ = await _open_one(store, sessions)
    author = uuid4()
    notes = []
    for index in range(3):
        note = await store.add_note(
            record.id,
            body=f"note {index}",
            author_id=None,
            entry=NewTimelineEntry(
                occurred_at=NOW + timedelta(minutes=index),
                entry_type=TimelineEntryType.note_added,
                summary="Note added",
                detail={"length": 6},
            ),
            now=NOW + timedelta(minutes=index),
        )
        assert note is not None
        notes.append(note)
    assert [n.body for n in notes] == ["note 0", "note 1", "note 2"]
    assert author  # the FK path is exercised by the API tests; None is the anonymous case

    first = await store.list_notes(record.id, limit=2, cursor=None)
    assert [n.body for n in first.items] == ["note 2", "note 1"]
    assert first.next_cursor is not None
    second = await store.list_notes(record.id, limit=2, cursor=first.next_cursor)
    assert [n.body for n in second.items] == ["note 0"]
    assert second.next_cursor is None

    detail = await store.get(record.id)
    assert detail is not None
    lines = [e for e in detail.timeline if e.entry_type is TimelineEntryType.note_added]
    assert len(lines) == 3
    assert lines[0].detail["note_id"] == str(notes[0].id)


async def test_a_note_on_a_case_that_does_not_exist_is_refused_not_orphaned(
    store: SqlIncidentStore,
) -> None:
    assert (
        await store.add_note(
            uuid4(),
            body="into the void",
            author_id=None,
            entry=NewTimelineEntry(
                occurred_at=NOW,
                entry_type=TimelineEntryType.note_added,
                summary="Note added",
            ),
            now=NOW,
        )
        is None
    )


async def test_the_timeline_pages_in_the_order_things_happened(
    store: SqlIncidentStore, sessions
) -> None:  # type: ignore[no-untyped-def]
    record, _alerts_ = await _open_one(store, sessions, count=2)
    await store.set_status(
        record.id,
        expected=IncidentStatus.new,
        target=IncidentStatus.triaging,
        closure_reason=None,
        entry=_change(IncidentStatus.triaging, NOW),
        now=NOW,
    )
    first = await store.list_timeline(record.id, limit=2, cursor=None)
    assert [e.entry_type for e in first.items] == [
        TimelineEntryType.alert_fired,
        TimelineEntryType.alert_fired,
    ]
    assert first.next_cursor is not None
    rest = await store.list_timeline(record.id, limit=2, cursor=first.next_cursor)
    assert [e.entry_type for e in rest.items] == [TimelineEntryType.status_change]
    assert rest.next_cursor is None


async def test_a_detail_carries_its_alerts_and_admits_when_it_cut_the_timeline(
    store: SqlIncidentStore, sessions
) -> None:  # type: ignore[no-untyped-def]
    record, alerts = await _open_one(store, sessions, count=2)
    whole = await store.get(record.id)
    assert whole is not None
    assert [a.rule_id for a in whole.alerts] == ["D-001", "D-001"]
    assert whole.alert_ids == tuple(a.id for a in alerts)
    assert whole.timeline_truncated is False

    clipped = await store.get(record.id, timeline_limit=1)
    assert clipped is not None
    assert clipped.timeline_truncated is True
    # The end that survives is the recent one, which is the part an analyst is working from.
    assert clipped.timeline[0].alert_id == alerts[-1].id


async def test_listing_incidents_pages_with_a_cursor(store: SqlIncidentStore, sessions) -> None:  # type: ignore[no-untyped-def]
    alerts = await _alerts(sessions, 3)
    for index, alert in enumerate(alerts):
        await store.open_case(
            _new_case((alert.id,), correlation_key=f"src_ip=10.10.0.{index}"),
            [],
            now=NOW + timedelta(minutes=index),
        )
    first = await store.list(IncidentFilter(limit=2))
    assert len(first.items) == 2
    assert first.next_cursor is not None
    second = await store.list(IncidentFilter(limit=2, cursor=first.next_cursor))
    assert len(second.items) == 1
    assert second.next_cursor is None
    numbers = [i.case_number for i in (*first.items, *second.items)]
    assert numbers == ["AEG-2026-0003", "AEG-2026-0002", "AEG-2026-0001"]


async def test_paging_across_entries_that_share_an_instant_loses_none_of_them(
    store: SqlIncidentStore, sessions
) -> None:  # type: ignore[no-untyped-def]
    """A keyset cursor has to compare `(time, id)` as a SQL row, not just the time.

    Ties are ordinary here: correlation writes an `observation` line at the window start, which
    is by construction the `occurred_at` of the earliest `alert_fired`. A predicate that
    compares only the timestamp drops every entry sharing the boundary instant, and the loss is
    silent — the page simply comes back short.
    """
    record, _alerts_ = await _open_one(store, sessions)
    tied = T0 - timedelta(hours=1)
    for index in range(3):
        await store.add_note(
            record.id,
            body=f"tied note {index}",
            author_id=None,
            entry=NewTimelineEntry(
                occurred_at=tied,
                entry_type=TimelineEntryType.observation,
                summary=f"same instant {index}",
            ),
            now=tied,
        )

    seen: list[str] = []
    cursor: str | None = None
    while True:
        page = await store.list_timeline(record.id, limit=1, cursor=cursor)
        seen.extend(e.summary for e in page.items)
        cursor = page.next_cursor
        if cursor is None:
            break
    assert sorted(s for s in seen if s.startswith("same instant")) == [
        "same instant 0",
        "same instant 1",
        "same instant 2",
    ]
    whole = await store.list_timeline(record.id, limit=50, cursor=None)
    assert len(seen) == len(whole.items), "paging one at a time saw every entry exactly once"

    # The same predicate, in the other direction, on notes.
    notes: list[str] = []
    cursor = None
    while True:
        page_n = await store.list_notes(record.id, limit=1, cursor=cursor)
        notes.extend(n.body for n in page_n.items)
        cursor = page_n.next_cursor
        if cursor is None:
            break
    assert sorted(notes) == ["tied note 0", "tied note 1", "tied note 2"]


async def test_a_case_closed_under_correlation_absorbs_nothing(
    store: SqlIncidentStore, sessions
) -> None:  # type: ignore[no-untyped-def]
    """ADR-023's invariant, at the one moment Chunk 16 made it reachable.

    Correlation reads the open case in one transaction and extends it in another. An analyst
    closing the case in between must not have new alerts buried in it: linking is permanent,
    because it flips the alert to `correlated` and `uq_incident_alerts_alert_id` means it can
    never be relinked to the new case it belongs in.
    """
    alerts = await _alerts(sessions, 3)
    record = await store.open_case(_new_case((alerts[0].id,)), [], now=NOW)

    closed = await store.set_status(
        record.id,
        expected=IncidentStatus.new,
        target=IncidentStatus.closed_false_positive,
        closure_reason="not our host",
        entry=_change(IncidentStatus.closed_false_positive, NOW),
        now=NOW,
    )
    assert closed is not None

    linked = await store.extend(
        record.id,
        [alerts[1].id, alerts[2].id],
        [
            NewTimelineEntry(
                occurred_at=a.first_seen,
                entry_type=TimelineEntryType.alert_fired,
                summary=f"{a.rule_id} fired",
                alert_id=a.id,
            )
            for a in alerts[1:]
        ],
        severity=4,
        severity_rationale={"result": 4},
        title="should not be applied",
        window_end=T0 + timedelta(hours=2),
        distinct_rule_count=2,
        now=NOW + timedelta(minutes=1),
    )
    assert linked == 0

    detail = await store.get(record.id)
    assert detail is not None
    assert detail.alert_ids == (alerts[0].id,), "no alert was buried in the closed case"
    assert detail.incident.title != "should not be applied"
    assert detail.incident.window_end == record.window_end, "a closed case's window is frozen"
    assert all(e.entry_type is not TimelineEntryType.alert_fired for e in detail.timeline)

    # The alerts are untouched, so the next correlation run opens a new case beside this one.
    still_open = await SqlAlertStore(sessions).list(AlertFilter(status=AlertStatus.open, limit=10))
    assert {a.id for a in still_open.items} >= {alerts[1].id, alerts[2].id}
