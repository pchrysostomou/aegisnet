"""Incidents over HTTP: viewers read cases, analysts work them, and every change is recorded.

The acceptance criteria of Milestone 3 are asserted here in the form a reviewer would check
them: a viewer receives `403` on every mutation, an illegal transition answers `409` and is
audit-logged as denied, and the timeline that comes back is ordered, typed, and contains the
status changes the test itself made.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

from aegisnet.domain.enums import AlertStatus, AuditResult, EntityType, TimelineEntryType
from aegisnet.domain.ports import AlertRecord, NewIncident, NewTimelineEntry
from tests.fakes import FakeWiring

pytestmark = pytest.mark.integration

INCIDENTS = "/api/v1/incidents"
T0 = datetime(2026, 9, 5, 10, 0, tzinfo=UTC)
"""Two hours before the shared fake clock, so the alerts precede anything an analyst does."""
HOST = "10.10.0.42"


def alert(rule: str, *, at: datetime, severity: int = 3) -> AlertRecord:
    return AlertRecord(
        id=uuid4(),
        rule_id=rule,
        rule_version=1,
        dedup_key=f"{rule}:src_ip={HOST}:{at.isoformat()}",
        severity=severity,
        confidence=0.9,
        severity_rationale={"result": severity},
        entity_type=EntityType.src_ip,
        entity_value=HOST,
        first_seen=at,
        last_seen=at + timedelta(seconds=30),
        evidence={"flows": 12},
        event_count=12,
        status=AlertStatus.correlated,
        created_at=at,
    )


@pytest.fixture
async def case(wiring: FakeWiring) -> UUID:
    """One open case with two alerts and two `alert_fired` lines, as correlation leaves it."""
    alerts = [alert("D-001", at=T0), alert("D-002", at=T0 + timedelta(minutes=2), severity=4)]
    for record in alerts:
        wiring.alert_store.rows[record.id] = record
    incident = await wiring.incident_store.open_case(
        NewIncident(
            correlation_key=f"src_ip={HOST}",
            title=f"D-001 and D-002 on {HOST}",
            severity=4,
            severity_rationale={"formula": "…", "result": 4, "escalated": False},
            window_start=T0,
            window_end=T0 + timedelta(minutes=3),
            distinct_rule_count=2,
            alert_ids=tuple(a.id for a in alerts),
        ),
        [
            NewTimelineEntry(
                occurred_at=a.first_seen,
                entry_type=TimelineEntryType.alert_fired,
                summary=f"{a.rule_id} fired on src_ip {HOST}",
                alert_id=a.id,
            )
            for a in alerts
        ],
        now=T0 + timedelta(minutes=5),
    )
    return incident.id


# ---------------------------------------------------------------- reads


def test_a_viewer_lists_and_opens_a_case(
    client: TestClient, viewer_headers: dict[str, str], case: UUID
) -> None:
    page = client.get(INCIDENTS, headers=viewer_headers)
    assert page.status_code == 200, page.text
    [item] = page.json()["items"]
    assert item["case_number"] == "AEG-2026-0001"
    assert item["status"] == "new" and item["severity"] == 4
    assert item["correlation_key"] == f"src_ip={HOST}"
    assert page.json()["next_cursor"] is None

    detail = client.get(f"{INCIDENTS}/{case}", headers=viewer_headers)
    assert detail.status_code == 200, detail.text
    body = detail.json()
    assert [a["rule_id"] for a in body["alerts"]] == ["D-001", "D-002"]
    assert [e["entry_type"] for e in body["timeline"]] == ["alert_fired", "alert_fired"]
    assert body["timeline_truncated"] is False
    # The workflow crosses the wire, so a client never keeps its own copy of the table.
    assert set(body["allowed_transitions"]) == {
        "triaging",
        "investigating",
        "closed_true_positive",
        "closed_false_positive",
        "closed_benign",
    }


def test_the_list_filters_by_status_severity_and_openness(
    client: TestClient, analyst_headers: dict[str, str], case: UUID
) -> None:
    def ids(**params: object) -> list[str]:
        response = client.get(INCIDENTS, params=params, headers=analyst_headers)
        assert response.status_code == 200, response.text
        return [i["id"] for i in response.json()["items"]]

    assert ids(status="new") == [str(case)]
    assert ids(status="triaging") == []
    assert ids(severity_min=5) == []
    assert ids(open=True) == [str(case)]

    client.post(
        f"{INCIDENTS}/{case}/status",
        json={"status": "closed_benign", "closure_reason": "lab traffic"},
        headers=analyst_headers,
    )
    assert ids(open=True) == []
    assert ids(status="closed_benign") == [str(case)]


def test_an_unknown_case_is_a_not_found_envelope_on_every_route(
    client: TestClient, analyst_headers: dict[str, str]
) -> None:
    missing = uuid4()
    for method, path, body in (
        ("GET", f"{INCIDENTS}/{missing}", None),
        ("GET", f"{INCIDENTS}/{missing}/timeline", None),
        ("GET", f"{INCIDENTS}/{missing}/notes", None),
        ("POST", f"{INCIDENTS}/{missing}/status", {"status": "triaging"}),
        ("POST", f"{INCIDENTS}/{missing}/notes", {"body": "hello"}),
    ):
        response = client.request(method, path, json=body, headers=analyst_headers)
        assert response.status_code == 404, (path, response.text)
        assert response.json()["error"]["code"] == "not_found"


# ---------------------------------------------------------------- the workflow


def test_an_analyst_walks_a_case_to_closed_and_the_timeline_tells_the_story(
    client: TestClient, wiring: FakeWiring, analyst_headers: dict[str, str], case: UUID
) -> None:
    for target in ("triaging", "investigating", "contained_recommended"):
        # The fake clock never moves by itself; a real one does, and the ordering assertion
        # below is about what the timeline says, not about how fast the test ran.
        wiring.clock.advance(timedelta(minutes=1))
        response = client.post(
            f"{INCIDENTS}/{case}/status", json={"status": target}, headers=analyst_headers
        )
        assert response.status_code == 200, response.text
        assert response.json()["status"] == target

    wiring.clock.advance(timedelta(minutes=1))
    closed = client.post(
        f"{INCIDENTS}/{case}/status",
        json={"status": "closed_true_positive", "closure_reason": "confirmed by the owner"},
        headers=analyst_headers,
    )
    assert closed.status_code == 200, closed.text
    assert closed.json()["closed_at"] is not None
    assert closed.json()["closure_reason"] == "confirmed by the owner"
    assert closed.json()["allowed_transitions"] == ["investigating"]

    timeline = client.get(f"{INCIDENTS}/{case}/timeline", headers=analyst_headers).json()
    assert [e["entry_type"] for e in timeline["items"]] == [
        "alert_fired",
        "alert_fired",
        "status_change",
        "status_change",
        "status_change",
        "status_change",
    ]
    moves = [e["detail"] for e in timeline["items"] if e["entry_type"] == "status_change"]
    assert [(m["from"], m["to"]) for m in moves] == [
        ("new", "triaging"),
        ("triaging", "investigating"),
        ("investigating", "contained_recommended"),
        ("contained_recommended", "closed_true_positive"),
    ]
    assert moves[-1]["closure_reason"] == "confirmed by the owner"

    changes = [e for e in wiring.audit_store.entries if e.action == "incident.status_changed"]
    assert len(changes) == 4
    assert changes[-1].result is AuditResult.success
    assert changes[-1].target_id == str(case)
    assert changes[-1].detail["from"] == "contained_recommended"
    assert changes[-1].detail["to"] == "closed_true_positive"
    assert changes[-1].detail["case_number"] == "AEG-2026-0001"
    assert changes[-1].actor_user_id is not None


def test_an_illegal_transition_is_409_and_is_audited_as_denied(
    client: TestClient, wiring: FakeWiring, analyst_headers: dict[str, str], case: UUID
) -> None:
    response = client.post(
        f"{INCIDENTS}/{case}/status",
        json={"status": "contained_recommended"},
        headers=analyst_headers,
    )
    assert response.status_code == 409, response.text
    assert response.json()["error"]["code"] == "conflict"

    refusals = [
        e for e in wiring.audit_store.entries if e.action == "incident.status_change_refused"
    ]
    assert len(refusals) == 1
    assert refusals[0].result is AuditResult.denied
    assert refusals[0].target_id == str(case)
    assert refusals[0].detail == {
        "from": "new",
        "to": "contained_recommended",
        "reason": "illegal_transition",
    }
    # Nothing moved, and the story does not claim anything happened.
    assert client.get(f"{INCIDENTS}/{case}", headers=analyst_headers).json()["status"] == "new"
    assert all(
        e.entry_type is not TimelineEntryType.status_change
        for e in wiring.incident_store.timeline[case]
    )


def test_repeating_a_status_a_case_already_holds_is_refused_rather_than_ignored(
    client: TestClient, analyst_headers: dict[str, str], case: UUID
) -> None:
    assert (
        client.post(
            f"{INCIDENTS}/{case}/status", json={"status": "triaging"}, headers=analyst_headers
        ).status_code
        == 200
    )
    replayed = client.post(
        f"{INCIDENTS}/{case}/status", json={"status": "triaging"}, headers=analyst_headers
    )
    assert replayed.status_code == 409, replayed.text


def test_a_closure_reason_on_a_move_that_closes_nothing_is_refused(
    client: TestClient, analyst_headers: dict[str, str], case: UUID
) -> None:
    response = client.post(
        f"{INCIDENTS}/{case}/status",
        json={"status": "triaging", "closure_reason": "because"},
        headers=analyst_headers,
    )
    assert response.status_code == 422, response.text
    assert response.json()["error"]["code"] == "validation_failed"


def test_an_unknown_status_never_reaches_the_workflow(
    client: TestClient, analyst_headers: dict[str, str], case: UUID
) -> None:
    response = client.post(
        f"{INCIDENTS}/{case}/status", json={"status": "resolved"}, headers=analyst_headers
    )
    assert response.status_code == 422, response.text


# ---------------------------------------------------------------- notes


def test_a_note_is_created_read_back_whole_and_audited_without_its_text(
    client: TestClient, wiring: FakeWiring, analyst_headers: dict[str, str], case: UUID
) -> None:
    body = "Owner says this is the nightly backup.\nClosing unless it repeats."
    created = client.post(f"{INCIDENTS}/{case}/notes", json={"body": body}, headers=analyst_headers)
    assert created.status_code == 201, created.text
    assert created.json()["body"] == body
    assert created.json()["author_id"] is not None

    listed = client.get(f"{INCIDENTS}/{case}/notes", headers=analyst_headers).json()
    assert [n["body"] for n in listed["items"]] == [body]

    (entry,) = (e for e in wiring.audit_store.entries if e.action == "incident.note_added")
    assert entry.detail == {"note_id": created.json()["id"], "length": len(body)}
    assert "backup" not in str(entry.detail)

    timeline = client.get(f"{INCIDENTS}/{case}/timeline", headers=analyst_headers).json()
    (line,) = (e for e in timeline["items"] if e["entry_type"] == "note_added")
    assert line["summary"] == "Note added"
    assert "backup" not in line["summary"] and "backup" not in str(line["detail"])


@pytest.mark.parametrize("body", ["", " ", "x" * 8001])
def test_a_note_that_cannot_be_stored_as_written_is_refused_by_field(
    client: TestClient, analyst_headers: dict[str, str], case: UUID, body: str
) -> None:
    response = client.post(
        f"{INCIDENTS}/{case}/notes", json={"body": body}, headers=analyst_headers
    )
    assert response.status_code == 422, response.text
    assert response.json()["error"]["code"] == "validation_failed"
    assert response.json()["error"]["details"][0]["field"].endswith("body")


def test_a_note_made_only_of_control_characters_names_the_field_itself(
    client: TestClient, analyst_headers: dict[str, str], case: UUID
) -> None:
    # Long enough to pass the schema's min_length, empty once the domain has cleaned it, so
    # this is the path where the service rather than Pydantic does the refusing.
    response = client.post(
        f"{INCIDENTS}/{case}/notes", json={"body": "\x00\x07\x1f"}, headers=analyst_headers
    )
    assert response.status_code == 422, response.text
    assert response.json()["error"]["details"] == [
        {"field": "body", "issue": "a note needs something in it"}
    ]


# ---------------------------------------------------------------- the role matrix


@pytest.mark.parametrize(
    ("path", "body"),
    [("status", {"status": "triaging"}), ("notes", {"body": "a viewer wrote this"})],
)
def test_a_viewer_reads_but_cannot_change_anything(
    client: TestClient,
    wiring: FakeWiring,
    viewer_headers: dict[str, str],
    case: UUID,
    path: str,
    body: dict[str, str],
) -> None:
    assert client.get(f"{INCIDENTS}/{case}", headers=viewer_headers).status_code == 200
    refused = client.post(f"{INCIDENTS}/{case}/{path}", json=body, headers=viewer_headers)
    assert refused.status_code == 403, refused.text
    assert refused.json()["error"]["code"] == "forbidden"
    assert wiring.audit_store.entries[-1].action == "rbac.denied"
    assert wiring.audit_store.entries[-1].detail["permission"] == "incidents.write"
    assert client.get(f"{INCIDENTS}/{case}", headers=viewer_headers).json()["status"] == "new"


def test_pagination_is_bounded_and_cursors_are_validated(
    client: TestClient, analyst_headers: dict[str, str], case: UUID
) -> None:
    assert client.get(INCIDENTS, params={"limit": 1000}, headers=analyst_headers).status_code == 422
    for route in ("", f"/{case}/timeline", f"/{case}/notes"):
        response = client.get(
            f"{INCIDENTS}{route}", params={"cursor": "not-a-cursor"}, headers=analyst_headers
        )
        assert response.status_code == 422, (route, response.text)
        assert response.json()["error"]["code"] == "validation_failed"
