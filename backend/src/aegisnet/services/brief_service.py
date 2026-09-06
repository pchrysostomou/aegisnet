"""Asking for a brief, and recording what came of it (Milestone 5, Chunk 23; ADR-031).

This is the only place the three halves meet: `domain/redaction` decides what may leave,
`adapters/perplexity` carries it, and `adapters/db/brief_store` keeps what came back. Keeping
them apart until here is what makes the boundary reviewable — nothing upstream knows an API
exists, and nothing downstream knows what a case looks like.

Two rules shape the whole of it:

* **A failure is a stored brief, not an error.** Every way the call can go wrong ends as a row
  with `status = failed` and a short reason. An incident is completely usable without a brief,
  and "the API was down at 03:10" is worth knowing later; an exception that vanished is not.
* **A brief never changes the case.** It appends a timeline line saying one was generated and
  writes an audit row. It cannot touch a severity, a status or an alert, and there is no field
  in the schema through which it could try (T-4.1).
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

from aegisnet.adapters.perplexity import (
    BriefUnavailableError,
    PerplexityClient,
    packet_hash,
)
from aegisnet.domain.briefs import InvestigationBrief, admit
from aegisnet.domain.enums import BriefSource, BriefStatus, TimelineEntryType
from aegisnet.domain.ports import (
    BriefRecord,
    BriefStore,
    CitationRecord,
    IncidentDetail,
    IncidentStore,
    NewBrief,
    NewTimelineEntry,
)
from aegisnet.domain.redaction import CaseEvidencePacket, Pseudonymizer, build_packet
from aegisnet.logging import get_logger

logger = get_logger(__name__)

OFFLINE_BRIEF = Path("briefs/offline-brief.json")
"""Relative to the samples directory. Served only when the feature is off or unconfigured."""

# The reasons that mean "nobody could have asked", as opposed to "we asked and it went wrong".
# Only these fall back to the committed fixture; a real failure is recorded as one.
OFFLINE_REASONS = frozenset({"disabled", "unconfigured"})

# Timeline lines that record what *this tool* did rather than what happened on the network.
# They are left out of the packet for two reasons. They are not evidence: a model asked to
# explain an incident should not be handed the note that somebody asked it to explain the
# incident. And leaving them in would make the packet change every time a brief was generated,
# so the content-addressed cache could never hit on the one case it exists for — an analyst
# asking about the same unchanged incident twice. Found by running `brief` twice against the
# stack and watching the hash move.
BOOKKEEPING = frozenset({TimelineEntryType.brief_generated, TimelineEntryType.report_exported})


class BriefIncidentNotFoundError(LookupError):
    """No such case."""


def utc_now() -> datetime:
    return datetime.now(tz=UTC)


class BriefService:
    def __init__(
        self,
        incidents: IncidentStore,
        briefs: BriefStore,
        client: PerplexityClient,
        *,
        samples_dir: Path,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self._incidents = incidents
        self._briefs = briefs
        self._client = client
        self._samples = samples_dir
        self._clock = clock

    async def list(self, incident_id: UUID) -> tuple[BriefRecord, ...]:
        await self._require(incident_id)
        return await self._briefs.list(incident_id)

    async def get(self, incident_id: UUID, version: int) -> BriefRecord | None:
        await self._require(incident_id)
        return await self._briefs.get(incident_id, version)

    async def generate(self, incident_id: UUID, *, actor: UUID | None = None) -> BriefRecord:
        """Build the packet, ask, and store the outcome either way."""
        detail = await self._require(incident_id)
        packet, _names = self._packet(detail)
        body = packet.serialise()

        try:
            result = await self._client.brief(body)
        except BriefUnavailableError as unavailable:
            offline = self._offline() if unavailable.reason in OFFLINE_REASONS else None
            if offline is None:
                return await self._store_failure(packet, unavailable, actor, incident_id)
            return await self._store_brief(
                packet, offline, BriefSource.offline_fixture, None, None, None, actor, incident_id
            )

        return await self._store_brief(
            packet,
            result.brief,
            BriefSource.perplexity,
            result.model,
            result.prompt_tokens,
            result.completion_tokens,
            actor,
            incident_id,
        )

    # ------------------------------------------------------------------ internals

    async def _require(self, incident_id: UUID) -> IncidentDetail:
        detail = await self._incidents.get(incident_id)
        if detail is None:
            raise BriefIncidentNotFoundError(str(incident_id))
        return detail

    def _packet(self, detail: IncidentDetail) -> tuple[CaseEvidencePacket, Pseudonymizer]:
        """The case, named field by field.

        Every argument below is spelled out on purpose: `build_packet` takes plain values, so
        there is no way to hand it a record wholesale and no way for a field to reach the
        outside because it happened to be on an object (ADR-029).
        """
        incident = detail.incident
        _kind, _, subject = incident.correlation_key.partition("=")
        return build_packet(
            case_number=incident.case_number,
            severity=incident.severity,
            status=incident.status.value,
            distinct_rule_count=incident.distinct_rule_count,
            window_start=incident.window_start,
            window_end=incident.window_end,
            subject=subject or incident.correlation_key,
            alerts=[
                {
                    "rule_id": alert.rule_id,
                    "severity": alert.severity,
                    "confidence": alert.confidence,
                    "event_count": alert.event_count,
                    "first_seen": alert.first_seen,
                    "last_seen": alert.last_seen,
                    "entity_value": alert.entity_value,
                    "evidence": alert.evidence,
                }
                for alert in detail.alerts
            ],
            timeline_summaries=[
                entry.summary for entry in detail.timeline if entry.entry_type not in BOOKKEEPING
            ],
        )

    def _offline(self) -> InvestigationBrief | None:
        """The committed answer a reviewer without a key sees. It goes through exactly the same
        admission as a real one — schema, citations, safety — because a fixture that could not
        be admitted would be a fixture that lies about what the feature does."""
        path = self._samples / OFFLINE_BRIEF
        if not path.is_file():
            return None
        try:
            return admit(json.loads(path.read_text(encoding="utf-8")))
        except (ValueError, OSError) as error:
            logger.warning("offline_brief_unusable", extra={"reason": type(error).__name__})
            return None

    async def _store_brief(
        self,
        packet: CaseEvidencePacket,
        brief: InvestigationBrief,
        source: BriefSource,
        model: str | None,
        prompt_tokens: int | None,
        completion_tokens: int | None,
        actor: UUID | None,
        incident_id: UUID,
    ) -> BriefRecord:
        now = self._clock()
        record = await self._briefs.create(
            NewBrief(
                incident_id=incident_id,
                status=BriefStatus.complete,
                source=source,
                packet_hash=_hash(packet),
                packet_truncated=packet.truncated,
                model=model,
                summary=brief.summary,
                limitations=brief.limitations,
                claims=[
                    {
                        "text": claim.text,
                        "kind": claim.kind,
                        "citations": list(claim.citations),
                        "verified": claim.verified,
                    }
                    for claim in brief.claims
                ],
                recommendations=[
                    {"action": advice.action.value, "detail": advice.detail}
                    for advice in brief.recommendations
                ],
                has_unverified=brief.has_unverified,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                requested_by=actor,
                citations=tuple(
                    CitationRecord(citation_id=c.id, url=c.url, title=c.title)
                    for c in brief.citations
                ),
            ),
            now,
        )
        await self._append(record, actor, now)
        logger.info(
            "brief_stored",
            extra={
                "version": record.version,
                "source": source.value,
                "unverified": brief.has_unverified,
                "packet": record.packet_hash[:12],
            },
        )
        return record

    async def _store_failure(
        self,
        packet: CaseEvidencePacket,
        unavailable: BriefUnavailableError,
        actor: UUID | None,
        incident_id: UUID,
    ) -> BriefRecord:
        now = self._clock()
        record = await self._briefs.create(
            NewBrief(
                incident_id=incident_id,
                status=BriefStatus.failed,
                source=BriefSource.perplexity,
                packet_hash=_hash(packet),
                packet_truncated=packet.truncated,
                failure_reason=unavailable.reason,
                requested_by=actor,
            ),
            now,
        )
        await self._append(record, actor, now)
        logger.warning(
            "brief_failed",
            extra={"version": record.version, "reason": unavailable.reason},
        )
        return record

    async def _append(self, record: BriefRecord, actor: UUID | None, now: datetime) -> None:
        """One line in the case's story. It says a brief happened and what came of it; the
        words themselves live in the brief, which nothing may rewrite."""
        summary = (
            f"Investigation brief v{record.version} generated"
            if record.status is BriefStatus.complete
            else f"Investigation brief v{record.version} could not be generated"
        )
        detail: dict[str, Any] = {
            "version": record.version,
            "status": record.status.value,
            "source": record.source.value,
        }
        if record.failure_reason:
            detail["reason"] = record.failure_reason
        if record.has_unverified:
            detail["has_unverified"] = True
        await self._incidents.add_timeline_entry(
            record.incident_id,
            NewTimelineEntry(
                occurred_at=now,
                entry_type=TimelineEntryType.brief_generated,
                summary=summary,
                detail=detail,
                actor_user_id=actor,
            ),
            now=now,
        )


def _hash(packet: CaseEvidencePacket) -> str:
    return packet_hash(packet.serialise())


__all__ = ["OFFLINE_BRIEF", "BriefIncidentNotFoundError", "BriefService"]
