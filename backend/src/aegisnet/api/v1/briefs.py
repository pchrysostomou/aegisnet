"""Investigation briefs (Milestone 5, Chunk 23; ADR-029 to ADR-031).

A viewer may read a brief, because it is a narrative about alerts they may already read. Only
an analyst may ask for one: generating a brief spends money and sends an evidence packet
outside the deployment, and both of those are decisions rather than lookups.

Generating never fails the request. Every way the call can go wrong is stored as a brief with
`status: failed` and a short reason, and answered `201` — the incident is completely usable
without a brief, and "the API was down" is worth recording rather than losing in a 502.
"""

from __future__ import annotations

from typing import Annotated, Final
from uuid import UUID

from fastapi import APIRouter, Depends, Path, Request, status

from aegisnet.api.deps import (
    AppServices,
    client_ip,
    correlation_id,
    enforce_limit,
    rate_limit,
    require,
    services,
)
from aegisnet.api.schemas import BriefOut
from aegisnet.domain.auth import Permission, Principal, PrincipalKind
from aegisnet.domain.enums import AuditResult, BriefStatus
from aegisnet.services.brief_service import BriefIncidentNotFoundError

DAY_SECONDS: Final = 24 * 60 * 60
"""The limiter's window index is `int(now // window_seconds)`, so at a day it *is* the UTC
day number — the same midnight `aegisnet:brief:budget:<date>` turns over on. One clock."""

router = APIRouter(prefix="/api/v1/incidents", tags=["briefs"])

MAX_VERSION = 10_000


class BriefNotFoundError(LookupError):
    """No brief at that version."""


@router.get(
    "/{incident_id}/briefs",
    response_model=list[BriefOut],
    summary="Every brief written about this case, newest version first",
    dependencies=[Depends(require(Permission.briefs_read)), Depends(rate_limit("read"))],
)
async def list_briefs(
    incident_id: UUID, svc: Annotated[AppServices, Depends(services)]
) -> list[BriefOut]:
    return [BriefOut.from_record(r) for r in await svc.briefs.list(incident_id)]


@router.get(
    "/{incident_id}/briefs/{version}",
    response_model=BriefOut,
    summary="One version of a case's brief",
    dependencies=[Depends(require(Permission.briefs_read)), Depends(rate_limit("read"))],
)
async def get_brief(
    incident_id: UUID,
    version: Annotated[int, Path(ge=1, le=MAX_VERSION)],
    svc: Annotated[AppServices, Depends(services)],
) -> BriefOut:
    record = await svc.briefs.get(incident_id, version)
    if record is None:
        raise BriefNotFoundError(f"no brief v{version}")
    return BriefOut.from_record(record)


@router.post(
    "/{incident_id}/briefs",
    status_code=status.HTTP_201_CREATED,
    response_model=BriefOut,
    summary="Ask for a brief about this case; a failure is stored, not raised",
    dependencies=[Depends(rate_limit("default"))],
)
async def generate_brief(
    incident_id: UUID,
    request: Request,
    svc: Annotated[AppServices, Depends(services)],
    principal: Annotated[Principal, Depends(require(Permission.briefs_generate))],
) -> BriefOut:
    # The narrower limit first, deliberately: `hit` increments whether or not it allows, so
    # checking the analyst first would let one stuck tab on one case spend that analyst's whole
    # day and lock them out of every other case. This way a loop costs the case its share and
    # costs the analyst part of theirs. Both are spent before the case is looked up, so probing
    # for case ids costs exactly what asking about a real case costs.
    #
    # Fail closed, like login and ingest and unlike a read: the budget these sit under is a
    # spending cap and an exposure cap, and an unreachable Redis is not a reason to send more
    # to a third party than the deployment agreed to (T-3.4).
    await enforce_limit(
        svc.limiter,
        "brief_incident",
        str(incident_id),
        limit=svc.settings.brief_incident_daily_limit,
        window_seconds=DAY_SECONDS,
        fail_open=False,
    )
    await enforce_limit(
        svc.limiter,
        "brief_user",
        principal.subject,
        limit=svc.settings.brief_user_daily_limit,
        window_seconds=DAY_SECONDS,
        fail_open=False,
    )

    actor = principal.id if principal.kind is PrincipalKind.user else None
    record = await svc.briefs.generate(incident_id, actor=actor)
    await svc.audit.record(
        "brief.generated",
        target_type="incident",
        target_id=str(incident_id),
        result=(
            AuditResult.success if record.status is BriefStatus.complete else AuditResult.error
        ),
        # The packet hash, not the packet: this records *which* question was asked, and the
        # question itself is reconstructible from the case.
        detail={
            "version": record.version,
            "status": record.status.value,
            "source": record.source.value,
            "packet_hash": record.packet_hash,
            "has_unverified": record.has_unverified,
            **({"reason": record.failure_reason} if record.failure_reason else {}),
        },
        principal=principal,
        actor_ip=client_ip(request),
        correlation_id=correlation_id(),
    )
    return BriefOut.from_record(record)


__all__ = ["BriefIncidentNotFoundError", "BriefNotFoundError", "router"]
