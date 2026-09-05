"""Alert reads (FR-5; Milestone 2). Viewers and above may read alerts: evidence is derived
and bounded by construction, so it carries nothing a payload would."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query

from aegisnet.api.deps import AppServices, rate_limit, require, services
from aegisnet.api.schemas import RULE_ID, AlertDetailOut, AlertPage
from aegisnet.domain.auth import Permission
from aegisnet.domain.enums import AlertStatus, EntityType
from aegisnet.domain.pagination import DEFAULT_LIMIT, MAX_LIMIT
from aegisnet.domain.ports import AlertFilter

router = APIRouter(prefix="/api/v1/alerts", tags=["alerts"])


@router.get(
    "",
    response_model=AlertPage,
    summary="Alerts, newest first, keyset-paginated",
    dependencies=[Depends(require(Permission.alerts_read)), Depends(rate_limit("read"))],
)
async def list_alerts(
    svc: Annotated[AppServices, Depends(services)],
    severity_min: Annotated[int | None, Query(ge=1, le=5)] = None,
    rule_id: Annotated[str | None, Query(pattern=RULE_ID.pattern)] = None,
    entity_type: EntityType | None = None,
    entity_value: Annotated[str | None, Query(min_length=1, max_length=253)] = None,
    status: AlertStatus | None = None,
    time_from: Annotated[datetime | None, Query(alias="from")] = None,
    time_to: Annotated[datetime | None, Query(alias="to")] = None,
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = DEFAULT_LIMIT,
    cursor: str | None = None,
) -> AlertPage:
    page = await svc.detection.list_alerts(
        AlertFilter(
            severity_min=severity_min,
            rule_id=rule_id,
            entity_type=entity_type,
            entity_value=entity_value,
            status=status,
            time_from=time_from,
            time_to=time_to,
            limit=limit,
            cursor=cursor,
        )
    )
    return AlertPage.from_page(page)


@router.get(
    "/{alert_id}",
    response_model=AlertDetailOut,
    summary="One alert with its sampled events and linked assets",
    dependencies=[Depends(require(Permission.alerts_read)), Depends(rate_limit("read"))],
)
async def get_alert(
    alert_id: UUID, svc: Annotated[AppServices, Depends(services)]
) -> AlertDetailOut:
    return AlertDetailOut.from_detail(await svc.detection.get_alert(alert_id))
