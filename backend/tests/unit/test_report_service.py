"""Gathering a case for a report (ADR-032).

The only judgement in `ReportService` is how much of a case a document is allowed to be, and
the branches that make that judgement are the ones a normal case never reaches: a story longer
than the detail carries, and a story longer than a document holds. Both are here, driven by a
stub store rather than by writing two thousand rows into a fake.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from ipaddress import ip_network
from uuid import UUID, uuid4

import pytest

from aegisnet.domain.assets import AssetNotFoundError
from aegisnet.domain.enums import (
    AlertStatus,
    AssetEnvironment,
    EntityType,
    EventType,
    IncidentStatus,
    IngestStatus,
    SampleRole,
    TimelineEntryType,
)
from aegisnet.domain.ports import (
    AlertDetail,
    AlertRecord,
    AssetRecord,
    BatchCounts,
    BatchSummary,
    EventRow,
    IncidentDetail,
    IncidentRecord,
    NoteRecord,
    Page,
    ResolvedAsset,
    TimelineEntryRecord,
)
from aegisnet.domain.reports import escape
from aegisnet.services.report_service import (
    MAX_NOTES,
    MAX_TIMELINE_ENTRIES,
    PROVENANCE_SAMPLES,
    ReportIncidentNotFoundError,
    ReportService,
)

pytestmark = pytest.mark.unit

T0 = datetime(2026, 9, 5, 9, 0, tzinfo=UTC)
CASE_ID = UUID("33333333-3333-3333-3333-333333333333")


def _incident() -> IncidentRecord:
    return IncidentRecord(
        id=CASE_ID,
        case_number="AEG-2026-0042",
        title="a long case",
        severity=3,
        severity_rationale={"result": 3},
        status=IncidentStatus.investigating,
        primary_asset_id=None,
        correlation_key="src_ip=10.0.0.1",
        window_start=T0,
        window_end=T0 + timedelta(hours=1),
        distinct_rule_count=1,
        assigned_to=None,
        closed_at=None,
        closure_reason=None,
        created_at=T0,
        updated_at=T0,
    )


def _entry(index: int) -> TimelineEntryRecord:
    return TimelineEntryRecord(
        id=uuid4(),
        incident_id=CASE_ID,
        occurred_at=T0 + timedelta(seconds=index),
        entry_type=TimelineEntryType.observation,
        summary=f"line {index}",
        detail={},
        alert_id=None,
        actor_user_id=None,
        created_at=T0 + timedelta(seconds=index),
    )


def _note(index: int) -> NoteRecord:
    return NoteRecord(
        id=uuid4(),
        incident_id=CASE_ID,
        author_id=None,
        body=f"note {index}",
        created_at=T0 + timedelta(seconds=index),
    )


class StubStore:
    """Just enough `IncidentStore` for a report, with pages counted so the test can see how
    many round trips a document costs."""

    def __init__(self, *, entries: int, notes: int, truncated: bool) -> None:
        self.timeline = [_entry(i) for i in range(entries)]
        self.notes = [_note(i) for i in range(notes)]
        self.truncated = truncated
        self.detail_missing = False
        self.timeline_pages = 0
        self.note_pages = 0

    async def get(self, incident_id: UUID) -> IncidentDetail | None:
        if self.detail_missing:
            return None
        assert incident_id == CASE_ID
        shown = self.timeline[-200:] if self.truncated else self.timeline
        return IncidentDetail(
            incident=_incident(),
            alert_ids=(),
            timeline=tuple(shown),
            alerts=(),
            timeline_truncated=self.truncated,
        )

    async def list_timeline(
        self, incident_id: UUID, *, limit: int, cursor: str | None
    ) -> Page[TimelineEntryRecord]:
        self.timeline_pages += 1
        return self._page(self.timeline, limit, cursor)

    async def list_notes(
        self, incident_id: UUID, *, limit: int, cursor: str | None
    ) -> Page[NoteRecord]:
        self.note_pages += 1
        return self._page(self.notes, limit, cursor)

    @staticmethod
    def _page(rows: list, limit: int, cursor: str | None):  # type: ignore[type-arg]
        start = int(cursor) if cursor else 0
        window = rows[start : start + limit]
        following = start + len(window)
        return Page(
            items=tuple(window),
            next_cursor=str(following) if following < len(rows) else None,
        )


class StubBriefs:
    async def list(self, incident_id: UUID) -> tuple[()]:
        return ()


class StubAlerts:
    """Alert details, keyed by alert id. A case with no alerts traces no provenance."""

    def __init__(self, details: dict[UUID, AlertDetail] | None = None) -> None:
        self.details = details or {}

    async def get(self, alert_id: UUID) -> AlertDetail | None:
        return self.details.get(alert_id)


class StubEvents:
    def __init__(self, batch_of: dict[UUID, UUID] | None = None) -> None:
        self.batch_of = batch_of or {}
        self.reads = 0

    async def get(self, event_id: UUID, *, include_payload: bool) -> EventRow | None:
        self.reads += 1
        batch_id = self.batch_of.get(event_id)
        return None if batch_id is None else _event(event_id, batch_id)


class StubIngest:
    def __init__(self, batches: dict[UUID, BatchSummary] | None = None) -> None:
        self.batches = batches or {}

    async def get_batch(self, batch_id: UUID) -> BatchSummary | None:
        return self.batches.get(batch_id)


class StubAssets:
    def __init__(
        self, named: AssetRecord | None = None, resolved: AssetRecord | None = None
    ) -> None:
        self.named = named
        self.resolved = resolved

    async def get(self, asset_id: UUID) -> AssetRecord:
        if self.named is None:
            raise AssetNotFoundError("unknown asset")
        return self.named

    async def resolve(self, address: object) -> ResolvedAsset | None:
        if self.resolved is None:
            return None
        return ResolvedAsset(asset=self.resolved, matched_cidr=ip_network("10.0.0.0/24"))


def _service(
    store: StubStore,
    *,
    alerts: StubAlerts | None = None,
    events: StubEvents | None = None,
    ingest: StubIngest | None = None,
    assets: StubAssets | None = None,
) -> ReportService:
    return ReportService(  # type: ignore[arg-type]
        store,
        StubBriefs(),  # type: ignore[arg-type]
        alerts=alerts or StubAlerts(),  # type: ignore[arg-type]
        events=events or StubEvents(),  # type: ignore[arg-type]
        ingest=ingest or StubIngest(),  # type: ignore[arg-type]
        assets=assets or StubAssets(),  # type: ignore[arg-type]
    )


async def test_a_short_case_costs_no_extra_query_for_its_timeline() -> None:
    """The detail already carried the whole story, and asking again would be a query for
    nothing."""
    store = StubStore(entries=10, notes=2, truncated=False)
    case_number, document = await _service(store).markdown(CASE_ID)

    assert case_number == "AEG-2026-0042"
    assert store.timeline_pages == 0
    assert "line 0" in document and "line 9" in document
    assert "beginning of a longer story" not in document


async def test_a_case_longer_than_the_detail_is_paged_from_the_beginning() -> None:
    """`IncidentDetail` carries the newest 200 lines, which is right for a screen and wrong for
    a document calling itself the case."""
    store = StubStore(entries=450, notes=0, truncated=True)
    _case_number, document = await _service(store).markdown(CASE_ID)

    assert store.timeline_pages == 3, "200 + 200 + 50, then the cursor ran out"
    assert "line 0" in document, "the beginning, which the detail had dropped"
    assert "line 449" in document
    assert "beginning of a longer story" not in document, "nothing was left out"


async def test_a_story_longer_than_a_document_stops_and_says_so() -> None:
    store = StubStore(entries=MAX_TIMELINE_ENTRIES + 300, notes=0, truncated=True)
    _case_number, document = await _service(store).markdown(CASE_ID)

    assert document.count(f"| {escape('observation')} |") == MAX_TIMELINE_ENTRIES
    assert "This is the beginning of a longer story" in document
    assert f"line {MAX_TIMELINE_ENTRIES + 299}" not in document


async def test_more_notes_than_a_document_holds_are_capped_and_flagged() -> None:
    store = StubStore(entries=1, notes=MAX_NOTES + 10, truncated=False)
    _case_number, document = await _service(store).markdown(CASE_ID)

    assert "These are the newest notes" in document
    assert document.count("note ") >= MAX_NOTES


async def test_an_unknown_case_is_refused_before_anything_is_gathered() -> None:
    store = StubStore(entries=5, notes=5, truncated=True)
    store.detail_missing = True
    with pytest.raises(ReportIncidentNotFoundError):
        await _service(store).markdown(CASE_ID)
    assert (store.timeline_pages, store.note_pages) == (0, 0)


# ---------------------------------------------------------------- assets and provenance


def _asset(hostname: str) -> AssetRecord:
    return AssetRecord(
        id=uuid4(),
        hostname=hostname,
        environment=AssetEnvironment.prod_sim,
        owner="team@example.test",
        criticality=4,
        tags=(),
        description=None,
        is_active=True,
        created_at=T0,
        updated_at=T0,
        networks=(),
    )


def _event(event_id: UUID, batch_id: UUID) -> EventRow:
    return EventRow(
        id=event_id,
        batch_id=batch_id,
        event_time=T0,
        ingested_at=T0,
        event_type=EventType.flow,
        flow_id=None,
        src_ip=None,
        dest_ip=None,
        src_port=None,
        dest_port=None,
        proto=None,
        app_proto=None,
        bytes_toserver=None,
        bytes_toclient=None,
        pkts_toserver=None,
        pkts_toclient=None,
        dns_query=None,
        dns_rrtype=None,
        dns_rcode=None,
        http_host=None,
        http_url_path=None,
        sig_signature=None,
        sig_category=None,
        sig_signature_id=None,
        sig_severity=None,
        payload=None,
    )


def _alert(entity: str) -> AlertRecord:
    return AlertRecord(
        id=uuid4(),
        rule_id="D-001",
        rule_version=1,
        dedup_key=f"D-001:{entity}",
        severity=3,
        confidence=0.8,
        severity_rationale={"result": 3},
        entity_type=EntityType.src_ip,
        entity_value=entity,
        first_seen=T0,
        last_seen=T0,
        evidence={},
        event_count=1,
        status=AlertStatus.correlated,
        created_at=T0,
    )


def _batch(batch_id: UUID) -> BatchSummary:
    return BatchSummary(
        batch_id=batch_id,
        status=IngestStatus.complete,
        source_label="scenario-import",
        dataset_id="demo-scenario-multi-stage-01",
        counts=BatchCounts(received=10, stored=10),
        started_at=T0,
        finished_at=T0,
    )


class CaseWithAlerts(StubStore):
    def __init__(self, alerts: list[AlertRecord]) -> None:
        super().__init__(entries=1, notes=0, truncated=False)
        self.alerts = alerts
        self.primary: UUID | None = None

    async def get(self, incident_id: UUID) -> IncidentDetail | None:
        base = await super().get(incident_id)
        assert base is not None
        record = _incident()
        if self.primary is not None:
            record = replace(record, primary_asset_id=self.primary)
        return replace(base, incident=record, alerts=tuple(self.alerts))


async def test_an_address_the_inventory_knows_becomes_an_owner() -> None:
    """FR-9.1's assets section. `10.0.0.5` is not an answer; "who owns it" is."""
    store = CaseWithAlerts([_alert("10.0.0.5")])
    service = _service(store, assets=StubAssets(resolved=_asset("app-01")))
    _case_number, document = await service.markdown(CASE_ID)

    assert escape("app-01") in document
    assert "No asset in the inventory matches" not in document


async def test_an_entity_that_is_not_an_address_is_not_looked_up() -> None:
    """A domain or a hostname is not something the inventory resolves, and asking it to would
    be a query per alert for an answer that cannot exist."""
    store = CaseWithAlerts([_alert("beacon.example.test")])
    service = _service(store, assets=StubAssets(resolved=_asset("never-used")))
    _case_number, document = await service.markdown(CASE_ID)
    assert escape("never-used") not in document
    assert "No asset in the inventory matches this case" in document


async def test_a_case_whose_primary_asset_was_deleted_still_renders() -> None:
    """A case outlives an asset row, and a report you cannot read is worst exactly then."""
    store = CaseWithAlerts([])
    store.primary = uuid4()
    _case_number, document = await _service(store, assets=StubAssets(named=None)).markdown(CASE_ID)
    assert "## Assets" in document
    assert "no owner named here" in document


async def test_the_appendix_traces_an_alert_back_to_the_import_it_rests_on() -> None:
    alert = _alert("10.0.0.9")
    event_id, batch_id = uuid4(), uuid4()
    store = CaseWithAlerts([alert])
    service = _service(
        store,
        alerts=StubAlerts(
            {alert.id: AlertDetail(alert=alert, events=((event_id, SampleRole.first),), assets=())}
        ),
        events=StubEvents({event_id: batch_id}),
        ingest=StubIngest({batch_id: _batch(batch_id)}),
    )
    _case_number, document = await service.markdown(CASE_ID)

    assert "## Appendix: where this evidence came from" in document
    assert escape("scenario-import") in document
    assert "Traced from a sample" not in document, "one event, and it was followed"


async def test_the_appendix_stops_after_a_sample_and_says_so() -> None:
    alert = _alert("10.0.0.9")
    events = [(uuid4(), SampleRole.first) for _ in range(PROVENANCE_SAMPLES + 3)]
    batch_id = uuid4()
    store = CaseWithAlerts([alert])
    stub_events = StubEvents({event_id: batch_id for event_id, _role in events})
    service = _service(
        store,
        alerts=StubAlerts({alert.id: AlertDetail(alert=alert, events=tuple(events), assets=())}),
        events=stub_events,
        ingest=StubIngest({batch_id: _batch(batch_id)}),
    )
    _case_number, document = await service.markdown(CASE_ID)

    assert stub_events.reads == PROVENANCE_SAMPLES, "bounded, not one query per event"
    assert "Traced from a sample of each alert" in document
