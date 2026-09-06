"""Briefs over HTTP (Milestone 5, Chunk 23; ADR-031).

Nothing here reaches the network: the wiring's client has no key and the feature is off, which
is exactly the state a reviewer's checkout is in — so these tests also happen to be the proof
that the offline path works.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from aegisnet.adapters.perplexity import PerplexityClient
from aegisnet.config import Settings
from aegisnet.domain.enums import AlertStatus, AuditResult, EntityType, TimelineEntryType
from aegisnet.domain.ports import AlertRecord, NewIncident, NewTimelineEntry
from aegisnet.services.brief_service import BriefService
from tests.conftest import make_settings
from tests.fakes import REPO_ROOT, FakeWiring

pytestmark = pytest.mark.integration

INCIDENTS = "/api/v1/incidents"
T0 = datetime(2026, 9, 5, 9, 0, tzinfo=UTC)
HOST = "10.10.0.42"


@pytest.fixture
async def case(wiring: FakeWiring) -> UUID:
    alert = AlertRecord(
        id=uuid4(),
        rule_id="D-004",
        rule_version=1,
        dedup_key="D-004:src_ip=10.10.0.42:x",
        severity=4,
        confidence=0.9,
        severity_rationale={"result": 4},
        entity_type=EntityType.src_ip,
        entity_value=HOST,
        first_seen=T0,
        last_seen=T0 + timedelta(minutes=14),
        evidence={"connections": 14, "jitter": 0.016, "destination": "203.0.113.55"},
        event_count=14,
        status=AlertStatus.correlated,
        created_at=T0,
    )
    wiring.alert_store.rows[alert.id] = alert
    incident = await wiring.incident_store.open_case(
        NewIncident(
            correlation_key=f"src_ip={HOST}",
            title=f"D-004 on {HOST}",
            severity=4,
            severity_rationale={"result": 4},
            window_start=T0,
            window_end=T0 + timedelta(minutes=14),
            distinct_rule_count=1,
            alert_ids=(alert.id,),
        ),
        [
            NewTimelineEntry(
                occurred_at=T0,
                entry_type=TimelineEntryType.alert_fired,
                summary=f"D-004 fired on src_ip {HOST}",
                alert_id=alert.id,
            )
        ],
        now=T0 + timedelta(minutes=20),
    )
    return incident.id


# ---------------------------------------------------------------- the offline path


def test_a_reviewer_with_no_key_still_sees_a_brief(
    client: TestClient, analyst_headers: dict[str, str], case: UUID
) -> None:
    """The committed fixture, clearly labelled. A checkout with no key is the normal state of
    this repository, so this is the path most people will meet."""
    created = client.post(f"{INCIDENTS}/{case}/briefs", headers=analyst_headers)
    assert created.status_code == 201, created.text
    body = created.json()

    assert body["status"] == "complete"
    assert body["source"] == "offline_fixture", "never presented as something a model said"
    assert body["model"] is None
    assert body["version"] == 1
    assert body["summary"]
    assert body["limitations"]
    assert [c["action"] for c in body["recommendations"]]
    assert all(c["url"].startswith("https://") for c in body["citations"])
    assert body["packet_hash"] and len(body["packet_hash"]) == 64


def test_the_offline_brief_is_admitted_the_same_way_a_real_one_would_be() -> None:
    """A fixture that could not pass the schema, the citation rule and the safety filter would
    be a fixture that lies about what the feature does."""
    service = BriefService(
        incidents=None,  # type: ignore[arg-type]
        briefs=None,  # type: ignore[arg-type]
        client=PerplexityClient(make_settings()),
        samples_dir=REPO_ROOT / "samples",
    )
    brief = service._offline()
    assert brief is not None
    assert brief.summary
    assert brief.has_unverified is False, "every external claim in the fixture cites a source"
    assert {c.kind for c in brief.claims} == {"observed", "external"}


# ---------------------------------------------------------------- versions and reads


def test_asking_twice_writes_a_second_version_rather_than_replacing_the_first(
    client: TestClient, analyst_headers: dict[str, str], case: UUID
) -> None:
    first = client.post(f"{INCIDENTS}/{case}/briefs", headers=analyst_headers).json()
    second = client.post(f"{INCIDENTS}/{case}/briefs", headers=analyst_headers).json()
    assert (first["version"], second["version"]) == (1, 2)
    assert first["id"] != second["id"]

    listed = client.get(f"{INCIDENTS}/{case}/briefs", headers=analyst_headers).json()
    assert [b["version"] for b in listed] == [2, 1], "newest first"

    one = client.get(f"{INCIDENTS}/{case}/briefs/1", headers=analyst_headers)
    assert one.status_code == 200
    assert one.json()["id"] == first["id"], "the first version is still exactly what it was"


def test_asking_twice_about_an_unchanged_case_asks_the_same_question(
    client: TestClient, analyst_headers: dict[str, str], case: UUID
) -> None:
    """Found by running `brief` twice against the stack: the first brief appends a timeline
    line, that line went into the packet, and the second packet therefore hashed differently —
    so the content-addressed cache could never hit on the one case it exists for. Lines that
    record what this tool did are not evidence about the incident."""
    first = client.post(f"{INCIDENTS}/{case}/briefs", headers=analyst_headers).json()
    second = client.post(f"{INCIDENTS}/{case}/briefs", headers=analyst_headers).json()
    assert first["packet_hash"] == second["packet_hash"], "the case did not change"
    assert first["version"] != second["version"], "but the brief is still a new version"


def test_a_viewer_reads_briefs_and_cannot_ask_for_one(
    client: TestClient,
    wiring: FakeWiring,
    viewer_headers: dict[str, str],
    analyst_headers: dict[str, str],
    case: UUID,
) -> None:
    client.post(f"{INCIDENTS}/{case}/briefs", headers=analyst_headers)

    assert client.get(f"{INCIDENTS}/{case}/briefs", headers=viewer_headers).status_code == 200
    refused = client.post(f"{INCIDENTS}/{case}/briefs", headers=viewer_headers)
    assert refused.status_code == 403
    assert wiring.audit_store.entries[-1].detail["permission"] == "briefs.generate"


def test_an_unknown_case_or_version_is_a_not_found_envelope(
    client: TestClient, analyst_headers: dict[str, str], case: UUID
) -> None:
    missing = uuid4()
    for method, path in (
        ("GET", f"{INCIDENTS}/{missing}/briefs"),
        ("POST", f"{INCIDENTS}/{missing}/briefs"),
        ("GET", f"{INCIDENTS}/{case}/briefs/9"),
    ):
        response = client.request(method, path, headers=analyst_headers)
        assert response.status_code == 404, (path, response.text)
        assert response.json()["error"]["code"] == "not_found"


# ---------------------------------------------------------------- what it records


def test_a_brief_appends_to_the_story_and_the_audit_trail_without_touching_the_case(
    client: TestClient, wiring: FakeWiring, analyst_headers: dict[str, str], case: UUID
) -> None:
    before = client.get(f"{INCIDENTS}/{case}", headers=analyst_headers).json()
    created = client.post(f"{INCIDENTS}/{case}/briefs", headers=analyst_headers).json()
    after = client.get(f"{INCIDENTS}/{case}", headers=analyst_headers).json()

    # T-4.1: narrative only. Nothing the brief said changed the case.
    for field in ("severity", "status", "distinct_rule_count", "title", "closure_reason"):
        assert before[field] == after[field], field
    assert [a["id"] for a in before["alerts"]] == [a["id"] for a in after["alerts"]]

    (line,) = (e for e in after["timeline"] if e["entry_type"] == "brief_generated")
    assert line["summary"] == "Investigation brief v1 generated"
    assert line["detail"]["source"] == "offline_fixture"

    (entry,) = (e for e in wiring.audit_store.entries if e.action == "brief.generated")
    assert entry.result is AuditResult.success
    assert entry.detail["packet_hash"] == created["packet_hash"]
    assert entry.detail["version"] == 1
    # The hash records *which* question was asked; the packet itself is not in the trail.
    assert "summary" not in entry.detail


def test_a_failure_is_stored_as_a_brief_and_leaves_the_case_usable(
    app: FastAPI,
    client: TestClient,
    wiring: FakeWiring,
    settings: Settings,
    analyst_headers: dict[str, str],
    case: UUID,
) -> None:
    """Every way the call can go wrong ends as a row an analyst can see, not a 502."""
    enabled = make_settings(
        brief_enabled=True,
        perplexity_api_key="pplx-" + "x" * 24,
        spool_dir=settings.spool_dir,
        secret_key=settings.secret_key.get_secret_value(),
        cookie_secure=False,
    )
    # The app captured its services when it started, so the swap happens there rather than on
    # the wiring — otherwise the route would still hold the client built at startup.
    app.state.services = replace(
        app.state.services,
        briefs=BriefService(
            wiring.incident_store,
            wiring.brief_store,
            PerplexityClient(
                enabled,
                transport=httpx.MockTransport(lambda _r: httpx.Response(503)),
                sleep=_instant,
            ),
            samples_dir=REPO_ROOT / "samples",
            clock=wiring.clock,
        ),
    )

    created = client.post(f"{INCIDENTS}/{case}/briefs", headers=analyst_headers)
    assert created.status_code == 201, "a failed brief is a stored answer, not an error"
    body = created.json()
    assert body["status"] == "failed"
    assert body["failure_reason"] == "http_503"
    assert body["summary"] is None
    assert body["packet_hash"], "we still record which question we tried to ask"

    assert client.get(f"{INCIDENTS}/{case}", headers=analyst_headers).status_code == 200
    (entry,) = (e for e in wiring.audit_store.entries if e.action == "brief.generated")
    assert entry.result is AuditResult.error
    assert entry.detail["reason"] == "http_503"


async def _instant(_seconds: float) -> None:
    return None
