"""Gathering a case so it can be written down (Milestone 5, Chunk 24; ADR-032).

`domain/reports` renders; this reads. The split is worth stating because it is what makes the
determinism claim testable: the renderer is a pure function of records, so a test can hand it
the same records twice and compare bytes without a database anywhere near it.

The one judgement here is how much of a case a document is allowed to be. `IncidentDetail`
carries the newest 200 timeline entries, which is right for a screen and wrong for a report
that calls itself the case — so this pages the whole story and all the notes up to a stated
cap, and when a case is longer than that the document says so rather than trailing off.
"""

from __future__ import annotations

from collections.abc import Sequence
from ipaddress import IPv4Address, IPv6Address, ip_address
from uuid import UUID

from aegisnet.domain.assets import AssetNotFoundError
from aegisnet.domain.pagination import MAX_LIMIT
from aegisnet.domain.ports import (
    AlertStore,
    AssetRecord,
    BatchSummary,
    BriefStore,
    EventReadStore,
    IncidentDetail,
    IncidentStore,
    IngestStore,
    NoteRecord,
    TimelineEntryRecord,
)
from aegisnet.domain.reports import render_report
from aegisnet.logging import get_logger
from aegisnet.services.asset_service import AssetService

MAX_TIMELINE_ENTRIES = 2_000
MAX_NOTES = 500
"""Where a document stops. Both are far above any case this project produces; they exist so a
report cannot be made unbounded by writing on a case in a loop (T-2.6)."""

PROVENANCE_ALERTS = 25
PROVENANCE_SAMPLES = 5
"""How far the appendix traces. An alert keeps a bounded sample of the events that produced
it, and following every one of a large case's samples would be a query storm for a table that
almost always has one row in it. The document says when it stopped early rather than implying
it saw everything."""


logger = get_logger(__name__)


def _as_address(value: str) -> IPv4Address | IPv6Address | None:
    """An entity value is an address, a hostname or a domain. Only the first resolves."""
    try:
        return ip_address(value)
    except ValueError:
        return None


class ReportIncidentNotFoundError(LookupError):
    """No such case."""


class ReportService:
    def __init__(
        self,
        incidents: IncidentStore,
        briefs: BriefStore,
        *,
        alerts: AlertStore,
        events: EventReadStore,
        ingest: IngestStore,
        assets: AssetService,
    ) -> None:
        self._incidents = incidents
        self._briefs = briefs
        self._alerts = alerts
        self._events = events
        self._ingest = ingest
        self._assets = assets

    async def markdown(self, incident_id: UUID, *, provenance: bool = True) -> tuple[str, str]:
        """The case number and the document, in that order.

        The case number comes back because the caller names the file with it and should not
        have to fetch the case a second time to learn it.

        `provenance` is the one thing about this document that depends on who asked. The
        appendix names ingest batches — their source label, their dataset and their counts —
        and those are `ingest.read`, which a viewer does not hold. The rest of the report is a
        re-rendering of what `incidents.read` already returns, so the honest statement of the
        determinism promise is: **the same case and the same permission produce the same
        bytes**, and a reader who may not see the appendix is told it was withheld rather than
        left to wonder whether the case had one.
        """
        detail = await self._incidents.get(incident_id)
        if detail is None:
            raise ReportIncidentNotFoundError(str(incident_id))

        timeline, timeline_complete = await self._timeline(detail)
        notes, notes_complete = await self._notes(incident_id)
        briefs = await self._briefs.list(incident_id)
        assets = await self._inventory(detail)
        batches: Sequence[BatchSummary] = ()
        provenance_complete = True
        if provenance:
            batches, provenance_complete = await self._provenance(detail)

        document = render_report(
            incident=detail.incident,
            alerts=detail.alerts,
            assets=assets,
            timeline=timeline,
            notes=notes,
            briefs=briefs,
            batches=batches,
            timeline_complete=timeline_complete,
            notes_complete=notes_complete,
            provenance_complete=provenance_complete,
            provenance_withheld=not provenance,
        )
        return detail.incident.case_number, document

    async def _timeline(self, detail: IncidentDetail) -> tuple[Sequence[TimelineEntryRecord], bool]:
        """The whole story, not the newest screenful.

        A case whose detail was not truncated already has all of it, and asking again would be
        a query for nothing.
        """
        if not detail.timeline_truncated:
            return detail.timeline, True

        gathered: list[TimelineEntryRecord] = []
        cursor: str | None = None
        # One row past the cap, so "complete" is decided by what exists rather than by which
        # page the cursor happened to run out on. Reading `< MAX` here would let a last page
        # that finishes the list carry the total over the cap and still call it complete.
        while len(gathered) <= MAX_TIMELINE_ENTRIES:
            page = await self._incidents.list_timeline(
                detail.incident.id, limit=MAX_LIMIT, cursor=cursor
            )
            gathered.extend(page.items)
            cursor = page.next_cursor
            # An empty page with a cursor would be a store bug, and it would be one that spins
            # this loop forever on a route a viewer can call.
            if cursor is None or not page.items:
                break
        return gathered[:MAX_TIMELINE_ENTRIES], len(gathered) <= MAX_TIMELINE_ENTRIES

    async def _inventory(self, detail: IncidentDetail) -> Sequence[AssetRecord]:
        """Whose machines this is about: the case's primary asset, plus whatever the inventory
        resolves each distinct alert address to. An address that resolves to nothing is not an
        error — it is an endpoint nobody has written down, which the document says instead."""
        found: dict[UUID, AssetRecord] = {}
        primary = detail.incident.primary_asset_id
        if primary is not None:
            record = await self._named_asset(primary)
            if record is not None:
                found[record.id] = record

        for value in sorted({alert.entity_value for alert in detail.alerts}):
            address = _as_address(value)
            if address is None:
                continue
            resolved = await self._assets.resolve(address)
            if resolved is not None:
                found[resolved.asset.id] = resolved.asset
        return tuple(found.values())

    async def _named_asset(self, asset_id: UUID) -> AssetRecord | None:
        """A case can outlive an asset row. A report that failed for that reason would be a
        report you cannot read exactly when you most want to."""
        try:
            return await self._assets.get(asset_id)
        except AssetNotFoundError:
            logger.info("report_primary_asset_missing", extra={"asset": str(asset_id)})
            return None

    async def _provenance(self, detail: IncidentDetail) -> tuple[Sequence[BatchSummary], bool]:
        """The ingest batches behind the sampled events of this case's alerts."""
        batch_ids: dict[UUID, None] = {}
        traced_all = len(detail.alerts) <= PROVENANCE_ALERTS
        for alert in detail.alerts[:PROVENANCE_ALERTS]:
            found = await self._alerts.get(alert.id)
            if found is None:
                # An alert we could not read is an alert we did not trace, and the document
                # should say so rather than imply the appendix is complete.
                traced_all = False
                continue
            if len(found.events) > PROVENANCE_SAMPLES:
                traced_all = False
            for event_id, _role in found.events[:PROVENANCE_SAMPLES]:
                row = await self._events.get(event_id, include_payload=False)
                if row is not None:
                    batch_ids[row.batch_id] = None

        batches = []
        for batch_id in batch_ids:
            summary = await self._ingest.get_batch(batch_id)
            if summary is not None:
                batches.append(summary)
        return batches, traced_all

    async def _notes(self, incident_id: UUID) -> tuple[Sequence[NoteRecord], bool]:
        gathered: list[NoteRecord] = []
        cursor: str | None = None
        while len(gathered) <= MAX_NOTES:
            page = await self._incidents.list_notes(incident_id, limit=MAX_LIMIT, cursor=cursor)
            gathered.extend(page.items)
            cursor = page.next_cursor
            if cursor is None or not page.items:
                break
        return gathered[:MAX_NOTES], len(gathered) <= MAX_NOTES


__all__ = ["MAX_NOTES", "MAX_TIMELINE_ENTRIES", "ReportIncidentNotFoundError", "ReportService"]
