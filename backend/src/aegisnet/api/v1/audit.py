"""Read-only audit route (FR-10.3). Admin only; there is no mutation route."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query

from aegisnet.api.deps import AppServices, rate_limit, require, services
from aegisnet.api.schemas import AuditOut, AuditPage
from aegisnet.domain.auth import Permission
from aegisnet.domain.enums import AuditResult
from aegisnet.domain.pagination import DEFAULT_LIMIT, MAX_LIMIT
from aegisnet.domain.ports import AuditFilter

router = APIRouter(prefix="/api/v1/audit", tags=["audit"])


@router.get(
    "",
    response_model=AuditPage,
    summary="Audit entries, newest first",
    dependencies=[Depends(require(Permission.audit_read)), Depends(rate_limit("read"))],
)
async def list_audit(
    svc: Annotated[AppServices, Depends(services)],
    action: Annotated[str | None, Query(max_length=64)] = None,
    actor: Annotated[UUID | None, Query()] = None,
    result: AuditResult | None = None,
    time_from: Annotated[datetime | None, Query(alias="from")] = None,
    time_to: Annotated[datetime | None, Query(alias="to")] = None,
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = DEFAULT_LIMIT,
    cursor: str | None = None,
) -> AuditPage:
    page = await svc.audit_read.list(
        AuditFilter(
            action=action,
            actor_user_id=actor,
            result=result,
            time_from=time_from,
            time_to=time_to,
            limit=limit,
            cursor=cursor,
        )
    )
    return AuditPage(items=[AuditOut.from_row(r) for r in page.items], next_cursor=page.next_cursor)
