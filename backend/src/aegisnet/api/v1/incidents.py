"""Incident cases: reading them, moving them through the workflow, writing on them.

Milestone 3, Chunk 16 (ADR-024). A viewer reads a case, because an incident is the readable
form of alerts a viewer may already read. Only an analyst changes one, and every change leaves
two records: a line in the case's own timeline, which is the story a human reads later, and a
row in the audit log, which is the evidence of who did it. A refused change leaves the audit
row too — an attempt that the workflow forbade is exactly the thing worth being able to look
up afterwards (T-2.3, T-2.5).
"""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, status

from aegisnet.api.deps import (
    AppServices,
    client_ip,
    correlation_id,
    rate_limit,
    require,
    services,
)
from aegisnet.api.schemas import (
    IncidentDetailOut,
    IncidentPage,
    NoteOut,
    NotePage,
    NoteRequest,
    StatusChangeRequest,
    TimelinePage,
)
from aegisnet.domain.auth import Permission, Principal, PrincipalKind
from aegisnet.domain.enums import AuditResult, IncidentStatus
from aegisnet.domain.pagination import DEFAULT_LIMIT, MAX_LIMIT
from aegisnet.domain.ports import IncidentFilter
from aegisnet.services.incident_service import StatusRefusedError

router = APIRouter(prefix="/api/v1/incidents", tags=["incidents"])


def _actor(principal: Principal) -> UUID | None:
    """The user who acted, or ``None`` for a service token.

    ``incident_timeline.actor_user_id`` references ``users``, so a token id must not be
    written there even though no token role holds ``incidents.write`` today.
    """
    return principal.id if principal.kind is PrincipalKind.user else None


@router.get(
    "",
    response_model=IncidentPage,
    summary="Incident cases, newest first, keyset-paginated",
    dependencies=[Depends(require(Permission.incidents_read)), Depends(rate_limit("read"))],
)
async def list_incidents(
    svc: Annotated[AppServices, Depends(services)],
    status_filter: Annotated[IncidentStatus | None, Query(alias="status")] = None,
    open_only: Annotated[bool, Query(alias="open")] = False,
    severity_min: Annotated[int | None, Query(ge=1, le=5)] = None,
    correlation_key: Annotated[str | None, Query(min_length=1, max_length=300)] = None,
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = DEFAULT_LIMIT,
    cursor: str | None = None,
) -> IncidentPage:
    page = await svc.incidents.list(
        IncidentFilter(
            status=status_filter,
            open_only=open_only,
            severity_min=severity_min,
            correlation_key=correlation_key,
            limit=limit,
            cursor=cursor,
        )
    )
    return IncidentPage.from_page(page)


@router.get(
    "/{incident_id}",
    response_model=IncidentDetailOut,
    summary="One case with its alerts, its recent timeline and where it may go next",
    dependencies=[Depends(require(Permission.incidents_read)), Depends(rate_limit("read"))],
)
async def get_incident(
    incident_id: UUID, svc: Annotated[AppServices, Depends(services)]
) -> IncidentDetailOut:
    return IncidentDetailOut.from_detail(await svc.incidents.get(incident_id))


@router.get(
    "/{incident_id}/timeline",
    response_model=TimelinePage,
    summary="The whole story in the order it happened, keyset-paginated",
    dependencies=[Depends(require(Permission.incidents_read)), Depends(rate_limit("read"))],
)
async def get_timeline(
    incident_id: UUID,
    svc: Annotated[AppServices, Depends(services)],
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = DEFAULT_LIMIT,
    cursor: str | None = None,
) -> TimelinePage:
    return TimelinePage.from_page(
        await svc.incidents.timeline(incident_id, limit=limit, cursor=cursor)
    )


@router.get(
    "/{incident_id}/notes",
    response_model=NotePage,
    summary="What analysts wrote on this case, newest first",
    dependencies=[Depends(require(Permission.incidents_read)), Depends(rate_limit("read"))],
)
async def get_notes(
    incident_id: UUID,
    svc: Annotated[AppServices, Depends(services)],
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = DEFAULT_LIMIT,
    cursor: str | None = None,
) -> NotePage:
    return NotePage.from_page(await svc.incidents.notes(incident_id, limit=limit, cursor=cursor))


@router.post(
    "/{incident_id}/status",
    response_model=IncidentDetailOut,
    summary="Move a case to another status, if the workflow allows it",
    dependencies=[Depends(rate_limit("default"))],
)
async def change_status(
    incident_id: UUID,
    body: StatusChangeRequest,
    request: Request,
    svc: Annotated[AppServices, Depends(services)],
    principal: Annotated[Principal, Depends(require(Permission.incidents_write))],
) -> IncidentDetailOut:
    try:
        change = await svc.incidents.change_status(
            incident_id,
            body.status,
            closure_reason=body.closure_reason,
            actor_user_id=_actor(principal),
        )
    except StatusRefusedError as refusal:
        # The route audits, not the exception handler: a handler cannot see the principal a
        # dependency resolved, and a denial nobody can attribute is not a denial record.
        await svc.audit.record(
            "incident.status_change_refused",
            target_type="incident",
            target_id=str(incident_id),
            result=AuditResult.denied,
            detail={
                "from": refusal.current.value,
                "to": refusal.target.value,
                "reason": refusal.reason,
            },
            principal=principal,
            actor_ip=client_ip(request),
            correlation_id=correlation_id(),
        )
        raise
    await svc.audit.record(
        "incident.status_changed",
        target_type="incident",
        target_id=str(change.incident.id),
        detail={
            "case_number": change.incident.case_number,
            "from": change.previous.value,
            "to": change.incident.status.value,
            # The reason itself stays on the case and in its timeline. The audit log records
            # that one was given and how long it was, so a later truncation would show.
            "closure_reason_chars": len(change.closure_reason or ""),
        },
        principal=principal,
        actor_ip=client_ip(request),
        correlation_id=correlation_id(),
    )
    return IncidentDetailOut.from_detail(await svc.incidents.get(incident_id))


@router.post(
    "/{incident_id}/notes",
    status_code=status.HTTP_201_CREATED,
    response_model=NoteOut,
    summary="Write a note on a case; notes are never edited",
    dependencies=[Depends(rate_limit("default"))],
)
async def add_note(
    incident_id: UUID,
    body: NoteRequest,
    request: Request,
    svc: Annotated[AppServices, Depends(services)],
    principal: Annotated[Principal, Depends(require(Permission.incidents_write))],
) -> NoteOut:
    note = await svc.incidents.add_note(incident_id, body.body, actor_user_id=_actor(principal))
    await svc.audit.record(
        "incident.note_added",
        target_type="incident",
        target_id=str(incident_id),
        # Never the body: the audit log caps a string at 512 characters and strips newlines,
        # so an audited copy of an 8 000-character note would differ from the note itself.
        detail={"note_id": str(note.id), "length": len(note.body)},
        principal=principal,
        actor_ip=client_ip(request),
        correlation_id=correlation_id(),
    )
    return NoteOut.from_record(note)
