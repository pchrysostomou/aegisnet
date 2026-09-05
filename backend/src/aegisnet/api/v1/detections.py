"""The detection registry, its runs, and the sweep trigger (Milestone 2, ADR-018)."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request, status

from aegisnet.api.deps import (
    AppServices,
    client_ip,
    correlation_id,
    rate_limit,
    require,
    services,
)
from aegisnet.api.schemas import DetectorRunOut, RuleOut, SweepAccepted, SweepRequest
from aegisnet.domain.auth import Permission, Principal
from aegisnet.services.detection_service import MAX_RUNS_LISTED

router = APIRouter(prefix="/api/v1/detections", tags=["detections"])


@router.get(
    "/rules",
    response_model=list[RuleOut],
    summary="The rules that ship, as recorded in the registry",
    dependencies=[Depends(require(Permission.alerts_read)), Depends(rate_limit("read"))],
)
async def list_rules(svc: Annotated[AppServices, Depends(services)]) -> list[RuleOut]:
    rules = await svc.detection.list_rules()
    if not rules:
        rules = tuple((await svc.detection.sync_rules()).values())
    return [RuleOut.from_record(r) for r in rules]


@router.get(
    "/runs",
    response_model=list[DetectorRunOut],
    summary="Recent detector runs, newest first",
    dependencies=[Depends(require(Permission.detections_read)), Depends(rate_limit("read"))],
)
async def list_runs(
    svc: Annotated[AppServices, Depends(services)],
    limit: Annotated[int, Query(ge=1, le=MAX_RUNS_LISTED)] = 50,
) -> list[DetectorRunOut]:
    return [DetectorRunOut.from_record(r) for r in await svc.detection.list_runs(limit=limit)]


@router.post(
    "/sweeps",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=SweepAccepted,
    summary="Queue a detection sweep over an interval of at most 24 hours",
    dependencies=[Depends(rate_limit("default"))],
)
async def request_sweep(
    body: SweepRequest,
    request: Request,
    svc: Annotated[AppServices, Depends(services)],
    principal: Annotated[Principal, Depends(require(Permission.detections_run))],
) -> SweepAccepted:
    svc.detection.validate_interval(body.time_from, body.time_to)
    message_id = await svc.enqueue_sweep(body.time_from, body.time_to)
    await svc.audit.record(
        "detection.sweep_requested",
        target_type="sweep",
        target_id=message_id,
        detail={"window_start": body.time_from, "window_end": body.time_to},
        principal=principal,
        actor_ip=client_ip(request),
        correlation_id=correlation_id(),
    )
    return SweepAccepted(
        window_start=body.time_from, window_end=body.time_to, message_id=message_id
    )
