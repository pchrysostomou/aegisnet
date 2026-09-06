"""The report renderer: the same case, the same bytes (ADR-032).

`make export` twice on a case nobody touched must produce identical files, so a difference
between two exports means the case changed. That is a stronger claim than "looks the same" and
almost every way of breaking it is invisible to the eye — a set iterated, a dictionary whose
keys moved, two rows sharing an instant swapping places, a naive datetime read against
whatever zone the machine is in. Each of those has a test here.
"""

from __future__ import annotations

import random
from datetime import UTC, datetime, timedelta
from ipaddress import ip_network
from uuid import UUID, uuid4

import pytest

from aegisnet.domain.enums import (
    AlertStatus,
    AssetEnvironment,
    BriefSource,
    BriefStatus,
    EntityType,
    IncidentStatus,
    IngestStatus,
    TimelineEntryType,
)
from aegisnet.domain.ports import (
    AlertRecord,
    AssetRecord,
    BatchCounts,
    BatchSummary,
    BriefRecord,
    CitationRecord,
    IncidentRecord,
    NetworkView,
    NoteRecord,
    TimelineEntryRecord,
)
from aegisnet.domain.reports import UNVERIFIED, escape, render_report

pytestmark = pytest.mark.unit

T0 = datetime(2026, 9, 5, 9, 0, tzinfo=UTC)
CASE_ID = UUID("11111111-1111-1111-1111-111111111111")


def incident(**overrides: object) -> IncidentRecord:
    values: dict[str, object] = {
        "id": CASE_ID,
        "case_number": "AEG-2026-0001",
        "title": "4 rules on 10.10.0.42: D-001, D-002, D-004, D-005",
        "severity": 5,
        "severity_rationale": {"result": 5, "member_max": 4, "escalated": True, "distinct": 4},
        "status": IncidentStatus.new,
        "primary_asset_id": None,
        "correlation_key": "src_ip=10.10.0.42",
        "window_start": T0,
        "window_end": T0 + timedelta(minutes=40),
        "distinct_rule_count": 4,
        "assigned_to": None,
        "closed_at": None,
        "closure_reason": None,
        "created_at": T0 + timedelta(minutes=45),
        "updated_at": T0 + timedelta(minutes=45),
    }
    values.update(overrides)
    return IncidentRecord(**values)  # type: ignore[arg-type]


def alert(rule: str, minute: int, **overrides: object) -> AlertRecord:
    values: dict[str, object] = {
        "id": uuid4(),
        "rule_id": rule,
        "rule_version": 1,
        "dedup_key": f"{rule}:src_ip=10.10.0.42:x",
        "severity": 4,
        "confidence": 0.9,
        "severity_rationale": {"result": 4},
        "entity_type": EntityType.src_ip,
        "entity_value": "10.10.0.42",
        "first_seen": T0 + timedelta(minutes=minute),
        "last_seen": T0 + timedelta(minutes=minute + 5),
        "evidence": {"connections": 14, "jitter": 0.016, "destination": "203.0.113.55"},
        "event_count": 14,
        "status": AlertStatus.correlated,
        "created_at": T0 + timedelta(minutes=minute + 6),
    }
    values.update(overrides)
    return AlertRecord(**values)  # type: ignore[arg-type]


def entry(minute: int, summary: str, kind: TimelineEntryType) -> TimelineEntryRecord:
    return TimelineEntryRecord(
        id=uuid4(),
        incident_id=CASE_ID,
        occurred_at=T0 + timedelta(minutes=minute),
        entry_type=kind,
        summary=summary,
        detail={},
        alert_id=None,
        actor_user_id=None,
        created_at=T0 + timedelta(minutes=minute),
    )


def note(body: str, minute: int = 50) -> NoteRecord:
    return NoteRecord(
        id=uuid4(),
        incident_id=CASE_ID,
        author_id=None,
        body=body,
        created_at=T0 + timedelta(minutes=minute),
    )


def brief(version: int = 1, **overrides: object) -> BriefRecord:
    values: dict[str, object] = {
        "id": uuid4(),
        "incident_id": CASE_ID,
        "version": version,
        "status": BriefStatus.complete,
        "source": BriefSource.perplexity,
        "packet_hash": "a" * 64,
        "packet_truncated": False,
        "model": "sonar",
        "summary": "asset-A did four things that are hard to explain together.",
        "limitations": "The packet carries no process context.",
        "claims": [
            {
                "text": "asset-A reached 40 ports.",
                "kind": "observed",
                "citations": [],
                "verified": True,
            },
            {
                "text": "Low-jitter callbacks are a documented pattern.",
                "kind": "external",
                "citations": [1],
                "verified": True,
            },
        ],
        "recommendations": [{"action": "investigate_host", "detail": "Confirm what opened them."}],
        "has_unverified": False,
        "failure_reason": None,
        "prompt_tokens": 900,
        "completion_tokens": 400,
        "requested_by": None,
        "created_at": T0 + timedelta(minutes=60),
        "citations": (
            CitationRecord(
                citation_id=1, url="https://attack.mitre.org/techniques/T1071/", title="T1071"
            ),
        ),
    }
    values.update(overrides)
    return BriefRecord(**values)  # type: ignore[arg-type]


def whole_case() -> dict[str, object]:
    return {
        "incident": incident(),
        "alerts": [alert("D-001", 0), alert("D-002", 10), alert("D-004", 20), alert("D-005", 30)],
        "timeline": [
            entry(0, "D-001 fired on src_ip 10.10.0.42", TimelineEntryType.alert_fired),
            entry(10, "D-002 fired on src_ip 10.10.0.42", TimelineEntryType.alert_fired),
            entry(60, "Investigation brief v1 generated", TimelineEntryType.brief_generated),
        ],
        "notes": [note("Confirmed with the owner: no backup runs at this hour.")],
        "briefs": [brief()],
    }


# ---------------------------------------------------------------- the promise


def test_the_same_case_renders_to_the_same_bytes() -> None:
    case = whole_case()
    assert render_report(**case) == render_report(**case)  # type: ignore[arg-type]


def test_the_order_the_rows_arrive_in_cannot_change_the_document() -> None:
    """Every store orders its own results, but the renderer is not allowed to depend on that:
    a query plan is not a contract, and two rows sharing an instant have no order at all."""
    case = whole_case()
    expected = render_report(**case)  # type: ignore[arg-type]

    shuffler = random.Random(20260906)
    for _ in range(20):
        shuffled = dict(case)
        for key in ("alerts", "timeline", "notes", "briefs"):
            items = list(case[key])  # type: ignore[call-overload]
            shuffler.shuffle(items)
            shuffled[key] = items
        assert render_report(**shuffled) == expected  # type: ignore[arg-type]


def test_two_rows_sharing_an_instant_keep_a_fixed_order() -> None:
    """The tie-break is the row's own id, which is why every sort here ends in one."""
    same_minute = [
        entry(5, "first", TimelineEntryType.observation),
        entry(5, "second", TimelineEntryType.observation),
        entry(5, "third", TimelineEntryType.observation),
    ]
    case = {**whole_case(), "timeline": same_minute}
    first = render_report(**case)  # type: ignore[arg-type]
    for _ in range(10):
        case["timeline"] = list(reversed(list(case["timeline"])))  # type: ignore[call-overload]
        assert render_report(**case) == first  # type: ignore[arg-type]


def test_a_dictionary_whose_keys_moved_renders_the_same() -> None:
    """`evidence` and `severity_rationale` are JSONB: nothing promises key order, and Python
    would happily print two orders for the same object graph."""
    forward = {"a": 1, "b": 2, "c": 3, "zzz": 4}
    backward = {"zzz": 4, "c": 3, "b": 2, "a": 1}
    alert_id = uuid4()
    one = render_report(
        incident=incident(severity_rationale=forward),
        alerts=[alert("D-001", 0, id=alert_id, evidence=forward)],
    )
    two = render_report(
        incident=incident(severity_rationale=backward),
        alerts=[alert("D-001", 0, id=alert_id, evidence=backward)],
    )
    assert one == two


def test_a_naive_timestamp_is_read_as_utc_and_not_as_the_machines_zone() -> None:
    """Otherwise the same row would render differently on two hosts, which is the one thing
    this module promises cannot happen."""
    aware = incident()
    naive = incident(
        window_start=aware.window_start.replace(tzinfo=None),
        created_at=aware.created_at.replace(tzinfo=None),
    )
    assert render_report(incident=naive) == render_report(incident=aware)


def test_the_same_instant_in_another_zone_renders_the_same_line() -> None:
    """`when` stamps a `Z`, so everything it prints must actually be UTC. An aware value from
    another zone is the same instant, and the document must say so rather than printing a local
    time under a UTC label."""
    from zoneinfo import ZoneInfo

    # The same instants the default carries, expressed somewhere else.
    elsewhere = incident(
        window_start=T0.astimezone(ZoneInfo("Europe/Athens")),
        created_at=(T0 + timedelta(minutes=45)).astimezone(ZoneInfo("America/Denver")),
    )
    assert render_report(incident=elsewhere) == render_report(incident=incident())
    assert "09:00:00Z" in render_report(incident=elsewhere), "and it is UTC, as the Z says"


def test_no_clock_reaches_the_document() -> None:
    """A "generated at" line is the obvious thing to put in a report and would make every
    export differ from every other. The document dates the case, never the export."""
    document = render_report(**whole_case())  # type: ignore[arg-type]
    for word in ("generated at", "exported at", "printed"):
        assert word not in document.lower()


# ---------------------------------------------------------------- what it says


def test_an_empty_case_still_renders_every_section() -> None:
    document = render_report(incident=incident())
    for heading in ("## The case", "## Alerts", "## Timeline", "## Notes", "## Investigation"):
        assert heading in document
    assert "_No alert is linked to this case._" in document
    assert "_Nobody has written on this case._" in document
    assert "_No brief has been generated for this case._" in document


def test_the_document_says_it_is_not_redacted() -> None:
    """The report carries the case verbatim, which is right for the operator reading it and
    wrong to discover later (ADR-029 covers the other direction)."""
    assert "**It is not redacted.**" in render_report(incident=incident())


def test_a_failed_brief_says_why_and_claims_nothing() -> None:
    failed = brief(
        status=BriefStatus.failed,
        summary=None,
        limitations=None,
        claims=[],
        recommendations=[],
        citations=(),
        failure_reason="http_503",
        model=None,
    )
    document = render_report(incident=incident(), briefs=[failed])
    assert "Version 1 — failed" in document
    assert "http_503" in document
    assert "#### Summary" not in document
    assert "The case above is unaffected" in document


def test_the_offline_sample_is_never_presented_as_something_a_model_said() -> None:
    document = render_report(
        incident=incident(), briefs=[brief(source=BriefSource.offline_fixture, model=None)]
    )
    assert "the offline sample committed to this repository, not a model" in document
    assert "model `sonar`" not in document


def test_an_uncited_external_claim_is_marked_rather_than_dropped() -> None:
    unverified = brief(
        claims=[
            {
                "text": "CVE-2026-9999 is being exploited in the wild.",
                "kind": "external",
                "citations": [],
                "verified": False,
            }
        ],
        has_unverified=True,
    )
    document = render_report(incident=incident(), briefs=[unverified])
    assert escape("CVE-2026-9999") in document, "the claim is kept"
    assert UNVERIFIED in document, "and marked"


def test_the_recommendations_say_what_they_are_not() -> None:
    document = render_report(incident=incident(), briefs=[brief()])
    assert "`investigate_host`" in document, "a list item, so still a code span"
    assert "things to look at, not things to do to a system" in document


def test_a_truncated_case_says_so_rather_than_trailing_off() -> None:
    document = render_report(
        incident=incident(),
        timeline=[entry(1, "something", TimelineEntryType.observation)],
        notes=[note("x")],
        timeline_complete=False,
        notes_complete=False,
    )
    assert "This is the beginning of a longer story" in document, "and says which part"
    assert "These are the newest notes" in document


def test_the_document_is_tidy() -> None:
    document = render_report(**whole_case())  # type: ignore[arg-type]
    assert document.endswith("\n")
    assert not document.endswith("\n\n")
    assert "\n\n\n" not in document, "no run of blank lines depends on which section ended"
    assert document.startswith("# AEG\\-2026\\-0001")


# ---------------------------------------------------------------- FR-9.1's other sections


def asset(hostname: str | None = "app-01", **overrides: object) -> AssetRecord:
    values: dict[str, object] = {
        "id": uuid4(),
        "hostname": hostname,
        "environment": AssetEnvironment.prod_sim,
        "owner": "platform@example.test",
        "criticality": 4,
        "tags": ("payments", "linux"),
        "description": None,
        "is_active": True,
        "created_at": T0,
        "updated_at": T0,
        "networks": (NetworkView(id=uuid4(), cidr=ip_network("10.10.0.0/24"), is_primary=True),),
    }
    values.update(overrides)
    return AssetRecord(**values)  # type: ignore[arg-type]


def batch(label: str = "scenario-import", **overrides: object) -> BatchSummary:
    values: dict[str, object] = {
        "batch_id": uuid4(),
        "status": IngestStatus.complete,
        "source_label": label,
        "dataset_id": "demo-scenario-multi-stage-01",
        "counts": BatchCounts(received=303, stored=303, duplicate=0, rejected=0),
        "started_at": T0,
        "finished_at": T0 + timedelta(seconds=4),
    }
    values.update(overrides)
    return BatchSummary(**values)  # type: ignore[arg-type]


def test_the_assets_section_names_who_to_ring() -> None:
    """FR-9.1: an address is not an answer. `10.10.0.42` tells a reader nothing about who
    owns the machine, and that is the part that turns a case into a decision."""
    document = render_report(incident=incident(), assets=[asset()])
    assert "## Assets" in document
    assert escape("app-01") in document
    assert escape("platform@example.test") in document, "the owner, escaped like everything else"
    assert escape("10.10.0.0/24") in document
    assert escape("payments") in document


def test_a_case_that_matched_no_asset_says_so_rather_than_showing_an_empty_table() -> None:
    document = render_report(incident=incident())
    assert "No asset in the inventory matches this case" in document
    assert "no owner named here" in document, "and the limitations repeat it"


def test_a_deactivated_asset_is_shown_as_one() -> None:
    document = render_report(incident=incident(), assets=[asset(is_active=False, tags=())])
    assert "**Deactivated** in the inventory" in document


def test_the_appendix_says_which_import_the_evidence_rests_on() -> None:
    """FR-9.1: a report that cannot name its provenance is a report nobody can check."""
    document = render_report(incident=incident(), batches=[batch()])
    assert "## Appendix: where this evidence came from" in document
    assert escape("scenario-import") in document
    assert escape("demo-scenario-multi-stage-01") in document
    assert "| 303 | 303 | 0 |" in document


def test_an_appendix_traced_from_a_sample_says_that_too() -> None:
    document = render_report(incident=incident(), batches=[batch()], provenance_complete=False)
    assert "Traced from a sample of each alert" in document


def test_the_document_states_what_it_is_not() -> None:
    document = render_report(**whole_case())  # type: ignore[arg-type]
    assert "## Limitations of this document" in document
    assert "not proof of what happened" in document
    assert "Detector accuracy is unmeasured" in document
    assert "changed nothing about the case and is not a finding" in document


def test_every_section_fr_9_1_names_is_present() -> None:
    """The requirement lists seven: summary, assets, timeline, alerts and evidence, the AI
    brief with its verification status, limitations, and the provenance appendix."""
    document = render_report(**whole_case(), assets=[asset()], batches=[batch()])  # type: ignore[arg-type]
    for heading in (
        "## The case",
        "## Assets",
        "## Alerts in this case",
        "## Timeline",
        "## Notes",
        "## Investigation briefs",
        "## Limitations of this document",
        "## Appendix: where this evidence came from",
    ):
        assert heading in document, heading


def test_the_new_sections_are_deterministic_too() -> None:
    assets = [asset("b-host"), asset("a-host"), asset(None)]
    batches = [batch("second", started_at=T0 + timedelta(hours=1)), batch("first")]
    expected = render_report(incident=incident(), assets=assets, batches=batches)
    for _ in range(10):
        assets.reverse()
        batches.reverse()
        assert render_report(incident=incident(), assets=assets, batches=batches) == expected
    assert expected.index("first") < expected.index("second"), "oldest import first"
