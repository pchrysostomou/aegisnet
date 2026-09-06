"""Correlation and the incident workflow as pure functions (ADR-023).

Written as scenarios rather than as data structures: a scan followed by an auth burst is one
case, the same two a day apart are two, and the same two on different hosts are two. Nothing
here touches a database, so what these tests pin is the *policy* — which is the part a
reviewer of a correlation engine should be able to read and disagree with.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from aegisnet.domain.correlation import (
    DEFAULT_JOIN_GAP,
    MAX_ALERTS_PER_GROUP,
    MAX_INCIDENT_SPAN,
    AlertFacts,
    CorrelationError,
    describe,
    group,
)
from aegisnet.domain.enums import EntityType
from aegisnet.domain.incidents import (
    CLOSED_STATUSES,
    ESCALATION_RULE_COUNT,
    MAX_CLOSURE_REASON_CHARS,
    MAX_NOTE_CHARS,
    TRANSITIONS,
    IllegalTransitionError,
    IncidentError,
    IncidentStatus,
    NoteBodyError,
    Window,
    case_number,
    check_transition,
    clean_closure_reason,
    clean_note_body,
    is_closed,
    severity_of,
    title_for,
)

pytestmark = pytest.mark.unit

T0 = datetime(2026, 9, 6, 10, 0, tzinfo=UTC)
HOST = "10.10.0.42"
OTHER = "10.10.0.99"


def alert(
    rule: str,
    *,
    at: datetime,
    duration: timedelta = timedelta(seconds=30),
    severity: int = 3,
    entity: str = HOST,
    entity_type: EntityType = EntityType.src_ip,
    number: int = 1,
) -> AlertFacts:
    """One alert, named by the rule that raised it and when it began."""
    return AlertFacts(
        id=UUID(int=number),
        rule_id=rule,
        severity=severity,
        entity_type=entity_type,
        entity_value=entity,
        first_seen=at,
        last_seen=at + duration,
    )


# ---------------------------------------------------------------- grouping


def test_a_multi_stage_attack_on_one_host_is_one_case() -> None:
    """The scenario docs/delivery-plan.md M3 names: scan, then failed logins, then a beacon,
    then a large upload, all from one asset within the hour."""
    alerts = [
        alert("D-001", at=T0, number=1),
        alert("D-002", at=T0 + timedelta(minutes=4), number=2),
        alert("D-004", at=T0 + timedelta(minutes=20), number=3),
        alert("D-005", at=T0 + timedelta(minutes=35), number=4),
    ]
    [case] = group(alerts)
    assert case.key == f"src_ip={HOST}"
    assert case.rule_ids == ("D-001", "D-002", "D-004", "D-005")
    assert len(case.alerts) == 4
    assert case.window_start == T0
    assert case.window_end == T0 + timedelta(minutes=35, seconds=30)


def test_four_distinct_rules_escalate_the_severity_by_one_step() -> None:
    alerts = [
        alert("D-001", at=T0, severity=3, number=1),
        alert("D-002", at=T0 + timedelta(minutes=2), severity=2, number=2),
        alert("D-004", at=T0 + timedelta(minutes=5), severity=3, number=3),
    ]
    [case] = group(alerts)
    severity = case.severity()
    assert (severity.member_max, severity.distinct_rules) == (3, 3)
    assert severity.escalated is True and severity.value == 4
    assert severity.rationale()["result"] == 4


def test_two_rules_do_not_escalate() -> None:
    alerts = [
        alert("D-001", at=T0, severity=4, number=1),
        alert("D-002", at=T0 + timedelta(minutes=1), severity=2, number=2),
    ]
    [case] = group(alerts)
    assert case.distinct_rule_count == 2 < ESCALATION_RULE_COUNT
    assert case.severity().escalated is False
    assert case.severity().value == 4, "still the worst of its members"


def test_the_same_rule_twice_is_one_rule() -> None:
    alerts = [
        alert("D-001", at=T0, number=1),
        alert("D-001", at=T0 + timedelta(minutes=1), number=2),
        alert("D-001", at=T0 + timedelta(minutes=2), number=3),
    ]
    [case] = group(alerts)
    assert case.distinct_rule_count == 1
    assert case.severity().escalated is False, "repetition is not corroboration"


def test_different_hosts_are_different_cases_however_close_in_time() -> None:
    """The whole of the no-guessing policy: correlation never decides that two entities are
    the same actor. A fragmented case is better than a confident wrong one."""
    alerts = [
        alert("D-001", at=T0, entity=HOST, number=1),
        alert("D-002", at=T0 + timedelta(seconds=5), entity=OTHER, number=2),
    ]
    cases = group(alerts)
    assert len(cases) == 2
    assert {c.entity_value for c in cases} == {HOST, OTHER}


def test_the_same_address_as_source_and_as_destination_is_not_the_same_entity() -> None:
    """`src_ip=10.10.0.42` and `dest_ip=10.10.0.42` are different keys. Merging them is a
    judgement about direction that belongs to an analyst, not to a grouping function."""
    alerts = [
        alert("D-001", at=T0, entity_type=EntityType.src_ip, number=1),
        alert("D-003", at=T0 + timedelta(minutes=1), entity_type=EntityType.dest_ip, number=2),
    ]
    assert len(group(alerts)) == 2


def test_a_gap_longer_than_the_join_window_starts_a_new_case() -> None:
    alerts = [
        alert("D-001", at=T0, number=1),
        alert("D-002", at=T0 + DEFAULT_JOIN_GAP + timedelta(minutes=1), number=2),
    ]
    first, second = group(alerts)
    assert first.rule_ids == ("D-001",) and second.rule_ids == ("D-002",)


def test_activity_that_keeps_going_keeps_one_case_open() -> None:
    """Each alert is measured against the end of the case so far, so a conversation that
    continues stays one story even when it outlasts the join window overall."""
    alerts = [
        alert("D-001", at=T0 + timedelta(minutes=50 * index), number=index + 1)
        for index in range(4)
    ]
    [case] = group(alerts)
    assert len(case.alerts) == 4
    assert case.window_end - case.window_start > DEFAULT_JOIN_GAP


def test_a_case_stops_growing_at_the_maximum_span() -> None:
    """Past a day, the next alert opens a new case: an incident has to stay something a human
    can read in one sitting."""
    alerts = [
        alert("D-001", at=T0 + timedelta(minutes=50 * index), number=index + 1)
        for index in range(30)
    ]
    cases = group(alerts)
    assert len(cases) > 1
    for case in cases:
        assert case.window_end - case.window_start <= MAX_INCIDENT_SPAN


def test_grouping_is_independent_of_the_order_alerts_arrive_in() -> None:
    """Idempotence starts here: the same alerts, shuffled, are the same cases."""
    alerts = [
        alert("D-001", at=T0, number=1),
        alert("D-002", at=T0 + timedelta(minutes=3), number=2),
        alert("D-004", at=T0 + timedelta(hours=5), number=3),
        alert("D-005", at=T0 + timedelta(minutes=1), entity=OTHER, number=4),
    ]
    forward = [(c.key, c.rule_ids, c.window_start) for c in group(alerts)]
    backward = [(c.key, c.rule_ids, c.window_start) for c in group(list(reversed(alerts)))]
    assert forward == backward


def test_alerts_presented_out_of_order_are_refused_rather_than_reordered_silently() -> None:
    """`group` sorts its input; `joins` does not, and says so. A grouping whose answer depends
    on input order is not idempotent, so the invariant is enforced rather than hoped for."""
    from aegisnet.domain.correlation import Proposal

    first = alert("D-001", at=T0 + timedelta(minutes=10), number=1)
    earlier = alert("D-002", at=T0, number=2)
    proposal = Proposal(first.key, first.entity_type, first.entity_value, (first,))
    with pytest.raises(CorrelationError, match="ascending"):
        proposal.joins(earlier)


def test_an_alert_with_a_naive_clock_is_refused() -> None:
    with pytest.raises(CorrelationError, match="timezone-aware"):
        AlertFacts(
            id=UUID(int=1),
            rule_id="D-001",
            severity=3,
            entity_type=EntityType.src_ip,
            entity_value=HOST,
            first_seen=T0.replace(tzinfo=None),
            last_seen=T0.replace(tzinfo=None),
        )


def test_a_group_stops_at_the_alert_cap() -> None:
    """A single entity that raises thousands of alerts is a broken sensor, not one story."""
    alerts = [
        alert("D-001", at=T0 + timedelta(seconds=index), number=index + 1)
        for index in range(MAX_ALERTS_PER_GROUP + 5)
    ]
    cases = group(alerts)
    assert len(cases) == 2
    assert len(cases[0].alerts) == MAX_ALERTS_PER_GROUP


def test_describe_summarises_without_naming_anything() -> None:
    summary = describe(group([alert("D-001", at=T0, number=1), alert("D-002", at=T0, number=2)]))
    assert summary == {"proposals": 1, "alerts": 2, "escalated": 0, "entities": 1}
    assert HOST not in str(summary)


# ---------------------------------------------------------------- the workflow


def test_a_new_case_can_be_triaged_investigated_or_closed() -> None:
    assert TRANSITIONS[IncidentStatus.new] == frozenset(
        {IncidentStatus.triaging, IncidentStatus.investigating, *CLOSED_STATUSES}
    )


@pytest.mark.parametrize("closed", sorted(CLOSED_STATUSES, key=lambda s: s.value))
def test_every_open_status_can_reach_every_closure(closed: IncidentStatus) -> None:
    """An analyst who has seen enough should not have to walk through the middle of the
    process to say so."""
    for status, allowed in TRANSITIONS.items():
        if is_closed(status):
            continue
        assert closed in allowed, f"{status.value} cannot close as {closed.value}"


@pytest.mark.parametrize("closed", sorted(CLOSED_STATUSES, key=lambda s: s.value))
def test_a_closed_case_reopens_only_into_investigating(closed: IncidentStatus) -> None:
    """Never straight back to `new`: that would erase the fact that it had been looked at."""
    assert TRANSITIONS[closed] == frozenset({IncidentStatus.investigating})
    check_transition(closed, IncidentStatus.investigating)
    with pytest.raises(IllegalTransitionError):
        check_transition(closed, IncidentStatus.new)


def test_moving_to_the_status_it_already_has_is_refused() -> None:
    """Almost always a client that lost track, and answering "done" would hide it."""
    with pytest.raises(IllegalTransitionError, match="already"):
        check_transition(IncidentStatus.triaging, IncidentStatus.triaging)


def test_every_status_has_somewhere_to_go_and_nowhere_undefined() -> None:
    assert set(TRANSITIONS) == set(IncidentStatus)
    for status, allowed in TRANSITIONS.items():
        assert allowed, f"{status.value} is a dead end"
        assert status not in allowed, f"{status.value} lists itself"
        assert allowed <= set(IncidentStatus)


# ---------------------------------------------------------------- severity, number, title


def test_severity_refuses_an_empty_case_or_an_impossible_member() -> None:
    with pytest.raises(IncidentError, match="at least one alert"):
        severity_of([], [])
    with pytest.raises(IncidentError, match="outside 1..5"):
        severity_of([6], ["D-001"])


def test_escalation_cannot_push_severity_past_the_ceiling() -> None:
    escalated = severity_of([5, 4, 3], ["D-001", "D-002", "D-004"])
    assert escalated.escalated is True and escalated.value == 5


def test_a_case_number_is_the_year_and_a_sequence_ordinal() -> None:
    assert case_number(2026, 1) == "AEG-2026-0001"
    assert case_number(2026, 12345) == "AEG-2026-12345", "the ordinal is not truncated"
    with pytest.raises(IncidentError):
        case_number(2026, 0)
    with pytest.raises(IncidentError):
        case_number(69, 1)


def test_a_title_is_derived_from_the_rules_and_the_subject() -> None:
    assert title_for(["D-001"], HOST) == f"D-001 on {HOST}"
    assert title_for(["D-002", "D-001"], HOST) == f"D-001 and D-002 on {HOST}"
    assert title_for(["D-001", "D-002", "D-004"], HOST, "ws-10.lab.example.test").startswith(
        "3 rules on ws-10.lab.example.test"
    )
    with pytest.raises(IncidentError):
        title_for([], HOST)


def test_a_window_grows_and_never_shrinks() -> None:
    window = Window(T0, T0 + timedelta(minutes=5))
    wider = window.extended_to(T0 - timedelta(minutes=1), T0 + timedelta(minutes=9))
    assert wider.start == T0 - timedelta(minutes=1)
    assert wider.end == T0 + timedelta(minutes=9)
    narrower = wider.extended_to(T0 + timedelta(minutes=2), T0 + timedelta(minutes=3))
    assert (narrower.start, narrower.end) == (wider.start, wider.end)
    with pytest.raises(IncidentError):
        Window(T0 + timedelta(minutes=1), T0)


# ---------------------------------------------------------------- analyst free text (ADR-024)


def test_a_note_keeps_its_paragraphs_and_loses_its_control_characters() -> None:
    assert clean_note_body("  one\ntwo\tthree  ") == "one\ntwo\tthree"
    assert clean_note_body("bell\x07 and null\x00") == "bell and null"
    # A Windows client's line endings become the newline the rest of the body already uses.
    assert clean_note_body("first\r\nsecond") == "first\nsecond"


@pytest.mark.parametrize("body", ["", "   ", "\x00", "\r\n", "\x1f\x7f"])
def test_a_note_that_is_empty_once_cleaned_is_refused(body: str) -> None:
    with pytest.raises(NoteBodyError) as error:
        clean_note_body(body)
    assert error.value.field == "body"
    assert error.value.issue == "a note needs something in it"


def test_a_note_is_refused_at_the_length_the_column_allows_not_truncated_to_it() -> None:
    assert clean_note_body("x" * MAX_NOTE_CHARS) == "x" * MAX_NOTE_CHARS
    with pytest.raises(NoteBodyError):
        clean_note_body("x" * (MAX_NOTE_CHARS + 1))


def test_a_closure_reason_that_says_nothing_is_no_reason_at_all() -> None:
    assert clean_closure_reason(None) is None
    assert clean_closure_reason("   ") is None
    assert clean_closure_reason("\x00\x07") is None
    assert clean_closure_reason("  known backup  ") == "known backup"


def test_a_closure_reason_has_its_own_shorter_limit() -> None:
    assert MAX_CLOSURE_REASON_CHARS < MAX_NOTE_CHARS
    assert clean_closure_reason("x" * MAX_CLOSURE_REASON_CHARS) is not None
    with pytest.raises(NoteBodyError) as error:
        clean_closure_reason("x" * (MAX_CLOSURE_REASON_CHARS + 1))
    assert error.value.field == "closure_reason"
