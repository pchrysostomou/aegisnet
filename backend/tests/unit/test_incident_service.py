"""Working a case, against fakes (ADR-024).

These tests are written against the four things a reviewer would want proved rather than
asserted: the workflow refuses what it says it refuses, a refusal carries enough to audit,
two analysts changing one case at the same moment do not both win, and what an analyst types
is bounded before it is stored anywhere.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest

from aegisnet.domain.enums import IncidentStatus, TimelineEntryType
from aegisnet.domain.incidents import (
    MAX_CLOSURE_REASON_CHARS,
    MAX_NOTE_CHARS,
    NoteBodyError,
)
from aegisnet.domain.ports import DETAIL_TIMELINE_LIMIT, NewIncident, NewTimelineEntry
from aegisnet.services.incident_service import (
    IncidentNotFoundError,
    IncidentService,
    StatusRefusedError,
)
from tests.fakes import FakeIncidentStore

pytestmark = pytest.mark.unit

NOW = datetime(2026, 9, 6, 12, 0, tzinfo=UTC)
T0 = datetime(2026, 9, 6, 10, 0, tzinfo=UTC)
ANALYST = uuid4()


class MovingClock:
    """A clock that advances a second each time it is read, so two writes in one test do not
    land on the same instant and hide an ordering bug."""

    def __init__(self, start: datetime = NOW) -> None:
        self.now = start

    def __call__(self) -> datetime:
        self.now += timedelta(seconds=1)
        return self.now


async def open_case(store: FakeIncidentStore, *, alerts: int = 1) -> tuple[IncidentService, UUID]:
    record = await store.open_case(
        NewIncident(
            correlation_key="src_ip=10.10.0.42",
            title="D-001 on 10.10.0.42",
            severity=3,
            severity_rationale={"result": 3},
            window_start=T0,
            window_end=T0 + timedelta(minutes=5),
            distinct_rule_count=1,
            alert_ids=tuple(uuid4() for _ in range(alerts)),
        ),
        [
            NewTimelineEntry(
                occurred_at=T0,
                entry_type=TimelineEntryType.alert_fired,
                summary="D-001 fired",
                alert_id=uuid4(),
            )
        ],
        now=NOW,
    )
    return IncidentService(store, clock=MovingClock()), record.id


async def service_with_case(**kwargs: int) -> tuple[IncidentService, FakeIncidentStore, UUID]:
    store = FakeIncidentStore()
    service, incident_id = await open_case(store, **kwargs)
    return service, store, incident_id


# ---------------------------------------------------------------- the workflow


async def test_a_legal_move_changes_the_status_and_writes_one_timeline_line() -> None:
    service, store, incident_id = await service_with_case()
    change = await service.change_status(
        incident_id, IncidentStatus.triaging, actor_user_id=ANALYST
    )
    assert change.previous is IncidentStatus.new
    assert change.incident.status is IncidentStatus.triaging
    entries = [
        e
        for e in store.timeline[change.incident.id]
        if e.entry_type is TimelineEntryType.status_change
    ]
    assert len(entries) == 1
    assert entries[0].summary == "Status changed from new to triaging"
    assert entries[0].detail == {"from": "new", "to": "triaging"}
    assert entries[0].actor_user_id == ANALYST


async def test_an_illegal_move_is_refused_with_the_facts_a_denial_record_needs() -> None:
    service, _store, incident_id = await service_with_case()
    with pytest.raises(StatusRefusedError) as refusal:
        await service.change_status(incident_id, IncidentStatus.contained_recommended)
    assert refusal.value.current is IncidentStatus.new
    assert refusal.value.target is IncidentStatus.contained_recommended
    assert refusal.value.reason == "illegal_transition"


async def test_moving_a_case_to_the_status_it_already_holds_is_refused() -> None:
    service, _store, incident_id = await service_with_case()
    with pytest.raises(StatusRefusedError) as refusal:
        await service.change_status(incident_id, IncidentStatus.new)
    assert refusal.value.reason == "illegal_transition"
    assert "already the status" in str(refusal.value)


async def test_a_second_analyst_working_from_a_stale_read_loses_the_race() -> None:
    service, store, incident_id = await service_with_case()

    # Both analysts saw `new`. The first one's change lands; the second arrives with the same
    # expectation and must be told the case moved rather than silently overwrite it.
    await service.change_status(incident_id, IncidentStatus.triaging)
    original = store.rows[incident_id]
    store.rows[incident_id] = replace(original, status=IncidentStatus.investigating)

    slow = IncidentService(
        _StaleStore(store, believed=IncidentStatus.triaging), clock=MovingClock()
    )
    with pytest.raises(StatusRefusedError) as refusal:
        await slow.change_status(incident_id, IncidentStatus.contained_recommended)
    assert refusal.value.reason == "status_changed_concurrently"
    assert store.rows[incident_id].status is IncidentStatus.investigating


class _StaleStore:
    """A store whose reads are one step behind its writes, which is what a race looks like
    from inside a request that read before somebody else committed."""

    def __init__(self, real: FakeIncidentStore, *, believed: IncidentStatus) -> None:
        self._real = real
        self._believed = believed

    async def get(self, incident_id, *, timeline_limit=DETAIL_TIMELINE_LIMIT):  # type: ignore[no-untyped-def]
        detail = await self._real.get(incident_id, timeline_limit=timeline_limit)
        if detail is None:
            return None
        return replace(detail, incident=replace(detail.incident, status=self._believed))

    def __getattr__(self, name: str) -> object:
        return getattr(self._real, name)


# ---------------------------------------------------------------- closing and reopening


async def test_closing_stamps_the_time_and_keeps_the_reason_on_the_case() -> None:
    service, _store, incident_id = await service_with_case()
    change = await service.change_status(
        incident_id, IncidentStatus.closed_false_positive, closure_reason="  a lab scan  "
    )
    assert change.incident.closed_at is not None
    assert change.incident.closure_reason == "a lab scan"
    assert change.closure_reason == "a lab scan"


async def test_reopening_clears_the_closure_but_the_story_still_says_why() -> None:
    service, store, incident_id = await service_with_case()
    await service.change_status(
        incident_id, IncidentStatus.closed_benign, closure_reason="known backup job"
    )
    reopened = await service.change_status(incident_id, IncidentStatus.investigating)
    assert reopened.incident.closed_at is None
    assert reopened.incident.closure_reason is None
    reasons = [
        e.detail.get("closure_reason")
        for e in store.timeline[incident_id]
        if e.entry_type is TimelineEntryType.status_change
    ]
    assert "known backup job" in reasons


async def test_a_blank_closure_reason_is_no_reason_rather_than_an_empty_one() -> None:
    service, _store, incident_id = await service_with_case()
    change = await service.change_status(
        incident_id, IncidentStatus.closed_true_positive, closure_reason="   "
    )
    assert change.incident.closure_reason is None


async def test_an_over_long_closure_reason_is_refused_by_field_name() -> None:
    service, _store, incident_id = await service_with_case()
    with pytest.raises(NoteBodyError) as error:
        await service.change_status(
            incident_id,
            IncidentStatus.closed_benign,
            closure_reason="x" * (MAX_CLOSURE_REASON_CHARS + 1),
        )
    assert error.value.field == "closure_reason"


# ---------------------------------------------------------------- notes


async def test_a_note_is_stored_whole_and_the_timeline_only_says_it_exists() -> None:
    service, store, incident_id = await service_with_case()
    body = "Checked the host.\nIt is a build agent.\tOwner confirmed."
    note = await service.add_note(incident_id, body, actor_user_id=ANALYST)
    assert note.body == body
    assert note.author_id == ANALYST
    (line,) = (
        e for e in store.timeline[incident_id] if e.entry_type is TimelineEntryType.note_added
    )
    assert line.summary == "Note added"
    assert line.detail == {"length": len(body), "note_id": str(note.id)}
    # The prose itself appears nowhere but the note.
    assert body not in line.summary and body not in str(line.detail)


async def test_control_characters_are_stripped_but_paragraphs_survive() -> None:
    service, _store, incident_id = await service_with_case()
    note = await service.add_note(incident_id, "line one\x00\x07\r\nline two\tindented  ")
    assert note.body == "line one\nline two\tindented"


@pytest.mark.parametrize("body", ["", "   ", "\x00\x07", "\n\n"])
async def test_a_note_with_nothing_in_it_is_refused(body: str) -> None:
    service, _store, incident_id = await service_with_case()
    with pytest.raises(NoteBodyError) as error:
        await service.add_note(incident_id, body)
    assert error.value.field == "body"


async def test_an_over_long_note_is_refused_rather_than_silently_truncated() -> None:
    service, _store, incident_id = await service_with_case()
    with pytest.raises(NoteBodyError):
        await service.add_note(incident_id, "x" * (MAX_NOTE_CHARS + 1))


async def test_notes_come_back_newest_first_and_page() -> None:
    service, _store, incident_id = await service_with_case()
    for n in range(3):
        await service.add_note(incident_id, f"note {n}")
    first = await service.notes(incident_id, limit=2)
    assert [n.body for n in first.items] == ["note 2", "note 1"]
    assert first.next_cursor is not None
    second = await service.notes(incident_id, limit=2, cursor=first.next_cursor)
    assert [n.body for n in second.items] == ["note 0"]
    assert second.next_cursor is None


# ---------------------------------------------------------------- reads


async def test_the_timeline_reads_in_the_order_things_happened_and_pages() -> None:
    service, _store, incident_id = await service_with_case()
    await service.change_status(incident_id, IncidentStatus.triaging)
    await service.change_status(incident_id, IncidentStatus.investigating)
    page = await service.timeline(incident_id, limit=2)
    assert [e.entry_type for e in page.items] == [
        TimelineEntryType.alert_fired,
        TimelineEntryType.status_change,
    ]
    rest = await service.timeline(incident_id, limit=2, cursor=page.next_cursor)
    assert [e.summary for e in rest.items] == ["Status changed from triaging to investigating"]


async def test_the_detail_carries_the_newest_entries_and_admits_when_it_cut() -> None:
    store = FakeIncidentStore()
    service, incident_id = await open_case(store)
    # Alternate so every move is legal, and produce more lines than a detail carries.
    for step in range(DETAIL_TIMELINE_LIMIT + 2):
        await service.change_status(
            incident_id,
            IncidentStatus.triaging if step % 2 == 0 else IncidentStatus.investigating,
        )
    detail = await service.get(incident_id)
    assert detail.timeline_truncated is True
    assert len(detail.timeline) == DETAIL_TIMELINE_LIMIT
    assert detail.timeline[-1].summary.endswith("to investigating")
    whole = await service.timeline(incident_id, limit=1)
    assert whole.items[0].entry_type is TimelineEntryType.alert_fired


@pytest.mark.parametrize(
    "call",
    [
        lambda s, i: s.get(i),
        lambda s, i: s.timeline(i),
        lambda s, i: s.notes(i),
        lambda s, i: s.change_status(i, IncidentStatus.triaging),
        lambda s, i: s.add_note(i, "hello"),
    ],
)
async def test_every_entry_point_refuses_a_case_that_does_not_exist(call) -> None:  # type: ignore[no-untyped-def]
    service, _store, _incident_id = await service_with_case()
    with pytest.raises(IncidentNotFoundError):
        await call(service, uuid4())
