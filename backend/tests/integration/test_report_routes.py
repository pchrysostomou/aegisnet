"""The report over HTTP (Milestone 5, Chunk 24; ADR-032).

The acceptance criterion Milestone 5 asks for is here — "exported Markdown is byte-identical
across two runs for the same incident" — and so is the thing that makes it true: the route
writes nothing, so exporting cannot change what the next export renders.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

from aegisnet.domain.enums import (
    AlertStatus,
    AuditResult,
    EntityType,
    IngestMethod,
    IngestStatus,
    SampleRole,
    SourceType,
    TimelineEntryType,
)
from aegisnet.domain.ports import (
    AlertRecord,
    BatchCounts,
    BatchProvenance,
    NewIncident,
    NewTimelineEntry,
)
from aegisnet.domain.reports import escape
from tests.fakes import FakeWiring, event_row_stub

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


# ---------------------------------------------------------------- the criterion


def test_two_exports_of_one_case_are_byte_identical(
    client: TestClient, analyst_headers: dict[str, str], case: UUID
) -> None:
    """The M5 acceptance criterion, on the bytes rather than on the parsed text."""
    first = client.get(f"{INCIDENTS}/{case}/report.md", headers=analyst_headers)
    second = client.get(f"{INCIDENTS}/{case}/report.md", headers=analyst_headers)
    assert first.status_code == 200, first.text
    assert first.content == second.content
    assert len(first.content) > 500, "and it is a document, not an empty one"


def test_exporting_changes_nothing_about_the_case(
    client: TestClient, wiring: FakeWiring, analyst_headers: dict[str, str], case: UUID
) -> None:
    """The reason the bytes match: nothing the report renders is written by exporting it.

    A report that recorded its own export in the timeline would change the case it renders —
    the defect Chunk 23 found in the evidence packet — so `report_exported` stays unwritten
    (ADR-032).
    """
    before = client.get(f"{INCIDENTS}/{case}", headers=analyst_headers).json()

    for _ in range(3):
        exported = client.get(f"{INCIDENTS}/{case}/report.md", headers=analyst_headers)
        assert exported.status_code == 200

    after = client.get(f"{INCIDENTS}/{case}", headers=analyst_headers).json()
    assert before == after, "the case is untouched, field for field"
    assert "report_exported" not in [e["entry_type"] for e in after["timeline"]]


def test_taking_a_copy_of_a_case_is_recorded(
    client: TestClient, wiring: FakeWiring, analyst_headers: dict[str, str], case: UUID
) -> None:
    """FR-10.3 names an export as an auditable event, and it is not an ordinary read: it is
    the whole case as plain text in a file somebody can forward. The audit log is not rendered
    by the report, so recording it cannot move the bytes."""
    exported = client.get(f"{INCIDENTS}/{case}/report.md", headers=analyst_headers)

    (entry,) = (e for e in wiring.audit_store.entries if e.action == "report.exported")
    assert entry.result is AuditResult.success
    assert entry.target_id == str(case)
    assert entry.detail["case_number"].startswith("AEG-")
    assert entry.detail["bytes"] == len(exported.content)
    # What was taken and how much of it — never a second copy of the case.
    assert "document" not in entry.detail and "summary" not in entry.detail


def test_a_brief_generated_between_two_exports_is_the_only_thing_that_changes_them(
    client: TestClient, analyst_headers: dict[str, str], case: UUID
) -> None:
    """Determinism is not "never changes": a difference between two exports must mean the case
    changed, and here it did."""
    before = client.get(f"{INCIDENTS}/{case}/report.md", headers=analyst_headers).content
    assert client.post(f"{INCIDENTS}/{case}/briefs", headers=analyst_headers).status_code == 201
    after = client.get(f"{INCIDENTS}/{case}/report.md", headers=analyst_headers).content
    again = client.get(f"{INCIDENTS}/{case}/report.md", headers=analyst_headers).content

    assert before != after, "the case gained a brief"
    assert after == again, "and then stopped changing"
    assert b"offline sample committed to this repository" in after


# ---------------------------------------------------------------- what comes back


def test_the_body_is_markdown_and_not_a_json_string(
    client: TestClient, analyst_headers: dict[str, str], case: UUID
) -> None:
    """FastAPI will happily serialise a `str` return value into a quoted JSON body. The route
    returns a Response subclass so that cannot happen, and this is what proves it."""
    response = client.get(f"{INCIDENTS}/{case}/report.md", headers=analyst_headers)
    assert response.headers["content-type"] == "text/markdown; charset=utf-8"
    assert response.content.startswith(b"# AEG"), response.content[:80]
    assert not response.content.startswith(b'"')


def test_a_case_number_with_a_newline_cannot_reach_the_header(
    client: TestClient, analyst_headers: dict[str, str], case: UUID
) -> None:
    """`$` in Python matches before a trailing newline too, and a header is a line-oriented
    format. The check is a `fullmatch`, so a value like that falls back to the fixed name."""
    from aegisnet.api.v1.reports import FALLBACK_FILENAME, _filename

    assert _filename("AEG-2026-0001") == "AEG-2026-0001.md"
    for hostile in ("AEG-2026-0001\n", "AEG-2026-0001\nX-Evil: 1", "aeg-2026-0001", "", "A-1-2"):
        assert _filename(hostile) == FALLBACK_FILENAME, hostile


def test_it_is_offered_as_a_file_named_after_the_case(
    client: TestClient, analyst_headers: dict[str, str], case: UUID
) -> None:
    response = client.get(f"{INCIDENTS}/{case}/report.md", headers=analyst_headers)
    disposition = response.headers["content-disposition"]
    assert disposition.startswith('attachment; filename="AEG-')
    assert disposition.endswith('.md"')
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"


def test_a_viewer_may_export_and_an_unknown_case_is_a_not_found_envelope(
    client: TestClient, viewer_headers: dict[str, str], analyst_headers: dict[str, str], case: UUID
) -> None:
    """Everything in the document is something a viewer can already read as JSON."""
    assert client.get(f"{INCIDENTS}/{case}/report.md", headers=viewer_headers).status_code == 200

    missing = client.get(f"{INCIDENTS}/{uuid4()}/report.md", headers=analyst_headers)
    assert missing.status_code == 404
    assert missing.json()["error"]["code"] == "not_found"
    assert missing.headers["content-type"].startswith("application/json"), (
        "an error is the envelope every other route uses, not Markdown"
    )


async def test_the_appendix_names_the_import_the_evidence_came_from(
    client: TestClient, wiring: FakeWiring, analyst_headers: dict[str, str], case: UUID
) -> None:
    """FR-9.1's provenance appendix, end to end through the wiring rather than through a stub.

    This assertion could not have been written before `FakeEventStore.get(include_payload=False)`
    was fixed: it used to fabricate a fresh row, so `row.batch_id` was a uuid belonging to no
    batch and the appendix always rendered its empty branch. A fake that answers differently
    from the port it stands in for hides exactly the code it is supposed to cover.
    """
    batch_id = await wiring.ingest_store.open_batch(
        BatchProvenance(
            source_type=SourceType.suricata_eve,
            source_label="sensor-lab-01",
            ingest_method=IngestMethod.registry_import,
            dataset_id="lab-capture-01",
        ),
        T0,
    )
    await wiring.ingest_store.finish_batch(
        batch_id, IngestStatus.complete, BatchCounts(received=1200, stored=1190, rejected=10), T0
    )
    event = event_row_stub()
    wiring.event_store.rows[event.id] = replace(event, batch_id=batch_id)

    (alert_id,) = wiring.alert_store.rows
    wiring.alert_store.links[alert_id] = (((event.id, SampleRole.first),), ())

    body = client.get(f"{INCIDENTS}/{case}/report.md", headers=analyst_headers).text
    assert "| Batch | Source | Dataset |" in body
    assert escape("sensor-lab-01") in body
    assert escape("lab-capture-01") in body
    assert "| 1200 | 1190 | 10 |" in body


def test_a_viewer_is_not_handed_the_provenance_a_separate_permission_gates(
    client: TestClient, viewer_headers: dict[str, str], analyst_headers: dict[str, str], case: UUID
) -> None:
    """The appendix names ingest batches — source label, dataset, line counts — and reading
    those is `ingest.read`, which a viewer does not hold. The report may not be a way around a
    permission, and a reader who cannot see the appendix is told so rather than left to wonder
    whether the case had one (ADR-032)."""
    viewer = client.get(f"{INCIDENTS}/{case}/report.md", headers=viewer_headers).text
    analyst = client.get(f"{INCIDENTS}/{case}/report.md", headers=analyst_headers).text

    assert "## Appendix: where this evidence came from" in viewer, "the section is still there"
    assert "`ingest.read`" in viewer and "does not hold" in viewer
    assert "| Batch | Source | Dataset |" not in viewer

    assert "this account does not hold" not in analyst
    # The rest of the document is the same for both: only the appendix moved.
    cut = "## Appendix: where this evidence came from"
    assert viewer.split(cut)[0] == analyst.split(cut)[0]


def test_the_document_carries_the_case_including_the_things_that_do_not_leave(
    client: TestClient, analyst_headers: dict[str, str], case: UUID
) -> None:
    """The redaction boundary is for the third party (ADR-029). This document is for the
    operator, so the real address is in it — and the document says so itself."""
    client.post(
        f"{INCIDENTS}/{case}/notes",
        headers=analyst_headers,
        json={"body": "Owner confirms no backup runs at this hour."},
    )
    body = client.get(f"{INCIDENTS}/{case}/report.md", headers=analyst_headers).text

    assert escape(HOST) in body, "the real address, not a pseudonym"
    assert "**It is not redacted.**" in body
    assert "Owner confirms no backup runs at this hour" in body
    assert escape("D-004") in body
    assert "203.0.113.55" in body, "the alert's evidence, in a fenced block as the rule wrote it"
