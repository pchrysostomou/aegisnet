"""Working a case: reading it, moving it through the workflow, writing on it (ADR-024).

The workflow itself is data and lives in ``domain/incidents.py``. What is here is the part
that needs state and an actor: checking a proposed move against the table, refusing it in a
way the caller and a later auditor can both act on, and making sure the case's own story and
the audit trail say the same thing about who did what.

Two properties are the point:

* **A refused transition is a refusal, not an error.** ``check_transition`` decides, the
  service raises, the API answers ``409``, and the route audits the attempt as denied. An
  analyst who tries something the workflow forbids leaves a record of having tried.
* **A status change is one write.** The status moves, the closure fields move with it and the
  timeline line is written in the same transaction, guarded by the status the caller believed
  the case was in. Two analysts deciding at once is ordinary; both succeeding is not.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from aegisnet.domain.enums import IncidentStatus, TimelineEntryType
from aegisnet.domain.incidents import (
    IllegalTransitionError,
    check_transition,
    clean_closure_reason,
    clean_note_body,
)
from aegisnet.domain.pagination import DEFAULT_LIMIT, check_limit
from aegisnet.domain.ports import (
    IncidentDetail,
    IncidentFilter,
    IncidentRecord,
    IncidentStore,
    NewTimelineEntry,
    NoteRecord,
    Page,
    TimelineEntryRecord,
)
from aegisnet.logging import get_logger

logger = get_logger(__name__)


class IncidentNotFoundError(LookupError):
    """No such case, or none this caller may be told about."""


class StatusRefusedError(IllegalTransitionError):
    """A status change the server would not make, with the facts a denial record needs.

    A subclass of the domain error on purpose: the API already maps ``IllegalTransitionError``
    to ``409``, so a refusal cannot accidentally become a ``500`` by arriving through a class
    nobody registered.
    """

    def __init__(
        self, *, current: IncidentStatus, target: IncidentStatus, reason: str, message: str
    ) -> None:
        self.current = current
        self.target = target
        self.reason = reason
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class StatusChange:
    """What a completed transition was, so the route can audit it without reading again."""

    incident: IncidentRecord
    previous: IncidentStatus
    closure_reason: str | None


def utc_now() -> datetime:
    return datetime.now(tz=UTC)


class IncidentService:
    def __init__(
        self, incidents: IncidentStore, *, clock: Callable[[], datetime] = utc_now
    ) -> None:
        self._incidents = incidents
        self._clock = clock

    async def list(self, query: IncidentFilter) -> Page[IncidentRecord]:
        check_limit(query.limit)
        return await self._incidents.list(query)

    async def get(self, incident_id: UUID) -> IncidentDetail:
        detail = await self._incidents.get(incident_id)
        if detail is None:
            raise IncidentNotFoundError(str(incident_id))
        return detail

    async def timeline(
        self, incident_id: UUID, *, limit: int = DEFAULT_LIMIT, cursor: str | None = None
    ) -> Page[TimelineEntryRecord]:
        await self._require(incident_id)
        return await self._incidents.list_timeline(
            incident_id, limit=check_limit(limit), cursor=cursor
        )

    async def notes(
        self, incident_id: UUID, *, limit: int = DEFAULT_LIMIT, cursor: str | None = None
    ) -> Page[NoteRecord]:
        await self._require(incident_id)
        return await self._incidents.list_notes(
            incident_id, limit=check_limit(limit), cursor=cursor
        )

    async def change_status(
        self,
        incident_id: UUID,
        target: IncidentStatus,
        *,
        closure_reason: str | None = None,
        actor_user_id: UUID | None = None,
    ) -> StatusChange:
        """Move a case, or refuse and say why.

        The refusal is a ``StatusRefusedError`` in both cases the workflow can produce: a move
        the table does not allow, and a move whose starting point somebody else changed first.
        They are told apart by ``reason``, because "you cannot do that" and "you are looking at
        a stale case" need different things from the analyst.
        """
        current = await self._require(incident_id)
        try:
            check_transition(current.status, target)
        except IllegalTransitionError as error:
            raise StatusRefusedError(
                current=current.status,
                target=target,
                reason="illegal_transition",
                message=str(error),
            ) from error

        reason = clean_closure_reason(closure_reason)
        now = self._clock()
        record = await self._incidents.set_status(
            incident_id,
            expected=current.status,
            target=target,
            closure_reason=reason,
            entry=NewTimelineEntry(
                occurred_at=now,
                entry_type=TimelineEntryType.status_change,
                summary=f"Status changed from {current.status.value} to {target.value}",
                # The reason lives here as well as on the case, because the case keeps only its
                # current one: reopening clears the column, and the story should still say why
                # somebody closed it at the time.
                detail={
                    "from": current.status.value,
                    "to": target.value,
                    **({"closure_reason": reason} if reason else {}),
                },
                actor_user_id=actor_user_id,
            ),
            now=now,
        )
        if record is None:
            raise StatusRefusedError(
                current=current.status,
                target=target,
                reason="status_changed_concurrently",
                message="the case moved on before this change could be applied",
            )
        logger.info(
            "incident_status_changed",
            extra={
                "case_number": record.case_number,
                "from": current.status.value,
                "to": target.value,
            },
        )
        return StatusChange(incident=record, previous=current.status, closure_reason=reason)

    async def add_note(
        self, incident_id: UUID, body: str, *, actor_user_id: UUID | None = None
    ) -> NoteRecord:
        cleaned = clean_note_body(body)
        now = self._clock()
        note = await self._incidents.add_note(
            incident_id,
            body=cleaned,
            author_id=actor_user_id,
            entry=NewTimelineEntry(
                occurred_at=now,
                entry_type=TimelineEntryType.note_added,
                # What the note said stays in the note. One copy of an analyst's prose is
                # enough, and it should be the copy nothing else rewrites.
                summary="Note added",
                detail={"length": len(cleaned)},
                actor_user_id=actor_user_id,
            ),
            now=now,
        )
        if note is None:
            raise IncidentNotFoundError(str(incident_id))
        return note

    async def _require(self, incident_id: UUID) -> IncidentRecord:
        detail = await self._incidents.get(incident_id, timeline_limit=1)
        if detail is None:
            raise IncidentNotFoundError(str(incident_id))
        return detail.incident


__all__ = [
    "IncidentNotFoundError",
    "IncidentService",
    "StatusChange",
    "StatusRefusedError",
]
