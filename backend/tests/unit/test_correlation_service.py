"""Correlation against fakes: what happens to a case when alerts keep arriving (ADR-023).

Three properties are what these tests are for, because they are what a reviewer would
disbelieve: a re-run adds nothing, a closed case is never quietly extended, and an alert that
is already in a case is left where it is.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from aegisnet.domain.enums import (
    AlertStatus,
    EntityType,
    IncidentStatus,
    TimelineEntryType,
)
from aegisnet.domain.ports import AlertRecord, NewIncident
from aegisnet.services.correlation_service import (
    CorrelationRunError,
    CorrelationService,
    summarise,
)
from tests.fakes import FakeAlertStore, FakeIncidentStore

pytestmark = pytest.mark.unit

T0 = datetime(2026, 9, 6, 10, 0, tzinfo=UTC)
NOW = datetime(2026, 9, 6, 12, 0, tzinfo=UTC)
WINDOW = (T0 - timedelta(hours=1), T0 + timedelta(days=1))
HOST = "10.10.0.42"


def stored_alert(
    rule: str,
    *,
    at: datetime,
    severity: int = 3,
    entity: str = HOST,
    entity_type: EntityType = EntityType.src_ip,
    status: AlertStatus = AlertStatus.open,
) -> AlertRecord:
    return AlertRecord(
        id=uuid4(),
        rule_id=rule,
        rule_version=1,
        dedup_key=f"{rule}:{entity_type.value}={entity}:{at.isoformat()}",
        severity=severity,
        confidence=0.8,
        severity_rationale={"result": severity},
        entity_type=entity_type,
        entity_value=entity,
        first_seen=at,
        last_seen=at + timedelta(seconds=30),
        evidence={},
        event_count=3,
        status=status,
        created_at=at,
    )


def service(
    alerts: list[AlertRecord], incidents: FakeIncidentStore | None = None
) -> tuple[CorrelationService, FakeIncidentStore, FakeAlertStore]:
    alert_store = FakeAlertStore()
    for alert in alerts:
        alert_store.rows[alert.id] = alert
    incident_store = incidents or FakeIncidentStore()
    return (
        CorrelationService(incident_store, alert_store, clock=lambda: NOW),
        incident_store,
        alert_store,
    )


async def test_a_multi_stage_scenario_becomes_one_escalated_case() -> None:
    """The acceptance criterion in docs/delivery-plan.md M3: scan, auth failures, beaconing
    and a large upload from one asset produce one incident with four alerts from four rules
    and an escalated severity."""
    alerts = [
        stored_alert("D-001", at=T0, severity=3),
        stored_alert("D-002", at=T0 + timedelta(minutes=5), severity=3),
        stored_alert("D-004", at=T0 + timedelta(minutes=25), severity=4),
        stored_alert("D-005", at=T0 + timedelta(minutes=40), severity=4),
    ]
    correlation, incidents, _ = service(alerts)

    outcome = await correlation.correlate(*WINDOW)

    assert (outcome.cases_opened, outcome.cases_extended) == (1, 0)
    assert outcome.alerts_correlated == 4
    [case] = incidents.rows.values()
    assert case.distinct_rule_count == 4
    assert case.severity == 5, "four rules escalate the worst member by one"
    assert case.severity_rationale["escalated"] is True
    assert case.case_number.startswith("AEG-2026-")
    assert case.status is IncidentStatus.new
    assert case.correlation_key == f"src_ip={HOST}"


async def test_the_timeline_records_every_alert_once_in_order() -> None:
    alerts = [
        stored_alert("D-001", at=T0),
        stored_alert("D-002", at=T0 + timedelta(minutes=5)),
    ]
    correlation, incidents, _ = service(alerts)
    await correlation.correlate(*WINDOW)

    [case] = incidents.rows.values()
    detail = await incidents.get(case.id)
    assert detail is not None
    kinds = [entry.entry_type for entry in detail.timeline]
    assert kinds == [TimelineEntryType.alert_fired, TimelineEntryType.alert_fired]
    assert [entry.occurred_at for entry in detail.timeline] == sorted(
        entry.occurred_at for entry in detail.timeline
    )
    assert detail.timeline[0].summary.startswith("D-001 fired on src_ip")
    assert detail.timeline[0].detail["rule_id"] == "D-001"


async def test_running_the_same_window_twice_changes_nothing() -> None:
    """Idempotence, the property M3's acceptance criteria name explicitly."""
    alerts = [
        stored_alert("D-001", at=T0),
        stored_alert("D-002", at=T0 + timedelta(minutes=3)),
    ]
    correlation, incidents, _ = service(alerts)

    first = await correlation.correlate(*WINDOW)
    second = await correlation.correlate(*WINDOW)

    assert first.cases_opened == 1 and first.alerts_correlated == 2
    assert second.cases_opened == 0 and second.cases_extended == 0
    assert second.alerts_correlated == 0
    assert len(incidents.rows) == 1
    [case] = incidents.rows.values()
    detail = await incidents.get(case.id)
    assert detail is not None
    assert len(detail.alert_ids) == 2
    assert len(detail.timeline) == 2, "a case says the same thing about an alert once"


async def test_a_later_alert_joins_the_open_case_rather_than_opening_another() -> None:
    first_batch = [stored_alert("D-001", at=T0)]
    correlation, incidents, alert_store = service(first_batch)
    await correlation.correlate(*WINDOW)

    late = stored_alert("D-004", at=T0 + timedelta(minutes=30), severity=4)
    alert_store.rows[late.id] = late
    outcome = await correlation.correlate(*WINDOW)

    assert (outcome.cases_opened, outcome.cases_extended) == (0, 1)
    assert len(incidents.rows) == 1
    [case] = incidents.rows.values()
    assert case.distinct_rule_count == 2
    assert case.severity == 4, "the case takes the worst of its members"
    assert case.window_end == late.last_seen


async def test_a_closed_case_is_never_extended_and_the_new_one_names_it() -> None:
    """A closed case is a judgement somebody made. New evidence gets a new case, which says
    which case came before it."""
    correlation, incidents, alert_store = service([stored_alert("D-001", at=T0)])
    await correlation.correlate(*WINDOW)
    [closed] = incidents.rows.values()
    incidents.rows[closed.id] = replace(
        closed,
        status=IncidentStatus.closed_false_positive,
        closed_at=NOW,
        closure_reason="benign backup client",
    )

    late = stored_alert("D-002", at=T0 + timedelta(minutes=20))
    alert_store.rows[late.id] = late
    outcome = await correlation.correlate(*WINDOW)

    assert outcome.cases_opened == 1 and outcome.cases_extended == 0
    assert len(incidents.rows) == 2
    [new_case] = [row for row in incidents.rows.values() if row.id != closed.id]
    assert new_case.correlation_key == closed.correlation_key
    detail = await incidents.get(new_case.id)
    assert detail is not None
    observations = [e for e in detail.timeline if e.entry_type is TimelineEntryType.observation]
    assert len(observations) == 1
    assert closed.case_number in observations[0].summary
    assert observations[0].detail["previous_status"] == "closed_false_positive"
    assert [o.superseded for o in outcome.outcomes] == [closed.case_number]


async def test_a_closed_case_from_long_ago_is_not_named() -> None:
    """Context, not noise: a case closed last month is not the predecessor of today."""
    correlation, incidents, alert_store = service([stored_alert("D-001", at=T0)])
    await correlation.correlate(*WINDOW)
    [closed] = incidents.rows.values()
    incidents.rows[closed.id] = replace(
        closed, status=IncidentStatus.closed_benign, closed_at=NOW, closure_reason="known good"
    )

    much_later = stored_alert("D-002", at=T0 + timedelta(hours=20))
    alert_store.rows[much_later.id] = much_later
    outcome = await correlation.correlate(*WINDOW)

    assert outcome.cases_opened == 1
    assert [o.superseded for o in outcome.outcomes] == [None]


async def test_an_alert_already_in_a_case_is_left_where_it_is() -> None:
    """Correlation adds; it never moves evidence between cases, because an analyst may have
    put it where it is."""
    alerts = [stored_alert("D-001", at=T0), stored_alert("D-002", at=T0 + timedelta(minutes=2))]
    correlation, incidents, _ = service(alerts)
    await correlation.correlate(*WINDOW)
    [case] = incidents.rows.values()
    before = dict(incidents.alerts)

    await correlation.correlate(*WINDOW)

    assert incidents.alerts == before
    assert all(incident == case.id for incident in incidents.alerts.values())


async def test_correlated_alerts_are_not_reconsidered() -> None:
    """The loader asks for open alerts only, so a case's members never regroup."""
    already = stored_alert("D-001", at=T0, status=AlertStatus.correlated)
    fresh = stored_alert("D-002", at=T0 + timedelta(minutes=1))
    correlation, incidents, _ = service([already, fresh])

    outcome = await correlation.correlate(*WINDOW)

    assert outcome.alerts_considered == 1
    [case] = incidents.rows.values()
    assert case.distinct_rule_count == 1


async def test_two_entities_produce_two_cases() -> None:
    alerts = [
        stored_alert("D-001", at=T0, entity="10.10.0.5"),
        stored_alert("D-002", at=T0 + timedelta(minutes=1), entity="10.10.0.9"),
    ]
    correlation, incidents, _ = service(alerts)
    outcome = await correlation.correlate(*WINDOW)
    assert outcome.cases_opened == 2
    assert {row.correlation_key for row in incidents.rows.values()} == {
        "src_ip=10.10.0.5",
        "src_ip=10.10.0.9",
    }


async def test_an_empty_window_is_not_an_error() -> None:
    correlation, incidents, _ = service([])
    outcome = await correlation.correlate(*WINDOW)
    assert (outcome.cases_opened, outcome.alerts_considered) == (0, 0)
    assert incidents.rows == {}


@pytest.mark.parametrize(
    ("start", "end", "message"),
    [
        (T0.replace(tzinfo=None), T0 + timedelta(hours=1), "timezone-aware"),
        (T0, T0, "ends after it starts"),
        (T0, T0 + timedelta(days=8), "at most"),
    ],
    ids=["naive", "empty", "too-long"],
)
async def test_an_interval_that_cannot_be_correlated_is_refused(
    start: datetime, end: datetime, message: str
) -> None:
    correlation, _, _ = service([])
    with pytest.raises(CorrelationRunError, match=message):
        await correlation.correlate(start, end)


async def test_the_summary_names_cases_but_no_alert_content() -> None:
    alerts = [stored_alert("D-001", at=T0), stored_alert("D-002", at=T0 + timedelta(minutes=1))]
    correlation, _, _ = service(alerts)
    summary = summarise(await correlation.correlate(*WINDOW))
    assert summary["cases_opened"] == 1
    assert summary["alerts_correlated"] == 2
    [case] = summary["cases"]  # type: ignore[misc]
    assert case["case_number"].startswith("AEG-")
    assert "evidence" not in str(summary)


async def test_a_case_closed_between_the_read_and_the_write_absorbs_nothing() -> None:
    """The window Chunk 16 opened: correlation reads a case as open, an analyst closes it, and
    correlation's extend arrives afterwards. The store refuses it — linking would be permanent,
    because the alert flips to `correlated` and can never be relinked to the case it belongs in.
    """
    incidents = FakeIncidentStore()
    opened = await incidents.open_case(
        NewIncident(
            correlation_key=f"src_ip={HOST}",
            title="D-001 on the host",
            severity=3,
            severity_rationale={"result": 3},
            window_start=T0,
            window_end=T0 + timedelta(minutes=1),
            distinct_rule_count=1,
            alert_ids=(uuid4(),),
        ),
        [],
        now=NOW,
    )
    incidents.rows[opened.id] = replace(
        opened, status=IncidentStatus.closed_benign, closed_at=NOW, closure_reason="handled"
    )
    linked = await incidents.extend(
        opened.id,
        [uuid4(), uuid4()],
        [],
        severity=5,
        severity_rationale={"result": 5},
        title="should not be applied",
        window_end=T0 + timedelta(hours=3),
        distinct_rule_count=3,
        now=NOW,
    )
    assert linked == 0
    frozen = incidents.rows[opened.id]
    assert frozen.title == "D-001 on the host"
    assert frozen.window_end == opened.window_end
    assert frozen.severity == 3
