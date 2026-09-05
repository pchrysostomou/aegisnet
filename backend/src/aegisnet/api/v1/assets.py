"""Asset inventory routes (FR-3). Mutations are audited with the fields that changed."""

from __future__ import annotations

from ipaddress import IPv4Address, IPv6Address
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
from aegisnet.api.schemas import AssetOut, AssetPage, BulkAssetsOut, BulkAssetsRequest, ResolveOut
from aegisnet.domain.assets import AssetPatch, AssetSpec
from aegisnet.domain.auth import Permission, Principal
from aegisnet.domain.enums import AssetEnvironment
from aegisnet.domain.pagination import DEFAULT_LIMIT, MAX_LIMIT
from aegisnet.domain.ports import AssetFilter, AssetRecord

router = APIRouter(prefix="/api/v1/assets", tags=["assets"])


def _snapshot(record: AssetRecord, fields: set[str]) -> dict[str, object]:
    """The audited before/after view of the fields a PATCH touched."""
    view: dict[str, object] = {}
    for field in sorted(fields):
        if field == "networks":
            view["networks"] = [str(n.cidr) for n in record.networks]
        else:
            view[field] = getattr(record, field)
    return view


@router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    response_model=AssetOut,
    summary="Create an asset",
    dependencies=[Depends(rate_limit("default"))],
)
async def create_asset(
    spec: AssetSpec,
    request: Request,
    svc: Annotated[AppServices, Depends(services)],
    principal: Annotated[Principal, Depends(require(Permission.assets_write))],
) -> AssetOut:
    record = await svc.assets.create(spec)
    await svc.audit.record(
        "asset.created",
        target_type="asset",
        target_id=str(record.id),
        detail={"hostname": record.hostname, "networks": [str(n.cidr) for n in record.networks]},
        principal=principal,
        actor_ip=client_ip(request),
        correlation_id=correlation_id(),
    )
    return AssetOut.from_record(record)


@router.post(
    "/bulk",
    status_code=status.HTTP_201_CREATED,
    response_model=BulkAssetsOut,
    summary="Create up to 500 assets atomically (seeding)",
    dependencies=[Depends(rate_limit("default"))],
)
async def bulk_create(
    body: BulkAssetsRequest,
    request: Request,
    svc: Annotated[AppServices, Depends(services)],
    principal: Annotated[Principal, Depends(require(Permission.assets_admin))],
) -> BulkAssetsOut:
    created = await svc.assets.bulk_create(body.assets)
    await svc.audit.record(
        "asset.bulk_created",
        target_type="asset",
        detail={"count": len(created), "hostnames": [a.hostname for a in created]},
        principal=principal,
        actor_ip=client_ip(request),
        correlation_id=correlation_id(),
    )
    return BulkAssetsOut(created=[AssetOut.from_record(a) for a in created])


@router.get(
    "/resolve",
    response_model=ResolveOut,
    summary="The asset owning an address (most specific CIDR wins)",
    dependencies=[Depends(require(Permission.assets_read)), Depends(rate_limit("read"))],
)
async def resolve(
    ip: IPv4Address | IPv6Address, svc: Annotated[AppServices, Depends(services)]
) -> ResolveOut:
    return ResolveOut.from_resolution(str(ip), await svc.assets.resolve(ip))


@router.get(
    "",
    response_model=AssetPage,
    summary="List assets",
    dependencies=[Depends(require(Permission.assets_read)), Depends(rate_limit("read"))],
)
async def list_assets(
    svc: Annotated[AppServices, Depends(services)],
    environment: AssetEnvironment | None = None,
    criticality_min: Annotated[int | None, Query(ge=1, le=5)] = None,
    tag: Annotated[str | None, Query(pattern=r"^[a-z0-9-]{1,32}$")] = None,
    q: Annotated[str | None, Query(max_length=253)] = None,
    include_inactive: bool = False,
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = DEFAULT_LIMIT,
    cursor: str | None = None,
) -> AssetPage:
    page = await svc.assets.list(
        AssetFilter(
            environment=environment,
            criticality_min=criticality_min,
            tag=tag,
            q=q,
            include_inactive=include_inactive,
            limit=limit,
            cursor=cursor,
        )
    )
    return AssetPage.from_page(page)


@router.get(
    "/{asset_id}",
    response_model=AssetOut,
    summary="One asset",
    dependencies=[Depends(require(Permission.assets_read)), Depends(rate_limit("read"))],
)
async def get_asset(asset_id: UUID, svc: Annotated[AppServices, Depends(services)]) -> AssetOut:
    return AssetOut.from_record(await svc.assets.get(asset_id))


@router.patch(
    "/{asset_id}",
    response_model=AssetOut,
    summary="Partial update; networks are replaced as a whole",
    dependencies=[Depends(rate_limit("default"))],
)
async def update_asset(
    asset_id: UUID,
    patch: AssetPatch,
    request: Request,
    svc: Annotated[AppServices, Depends(services)],
    principal: Annotated[Principal, Depends(require(Permission.assets_write))],
) -> AssetOut:
    before = await svc.assets.get(asset_id)
    after = await svc.assets.update(asset_id, patch)
    touched = set(patch.model_fields_set)
    await svc.audit.record(
        "asset.updated",
        target_type="asset",
        target_id=str(asset_id),
        detail={"before": _snapshot(before, touched), "after": _snapshot(after, touched)},
        principal=principal,
        actor_ip=client_ip(request),
        correlation_id=correlation_id(),
    )
    return AssetOut.from_record(after)


@router.delete(
    "/{asset_id}",
    response_model=AssetOut,
    summary="Soft delete: the asset is deactivated, history is kept",
    dependencies=[Depends(rate_limit("default"))],
)
async def deactivate_asset(
    asset_id: UUID,
    request: Request,
    svc: Annotated[AppServices, Depends(services)],
    principal: Annotated[Principal, Depends(require(Permission.assets_admin))],
) -> AssetOut:
    record = await svc.assets.deactivate(asset_id)
    await svc.audit.record(
        "asset.deactivated",
        target_type="asset",
        target_id=str(asset_id),
        detail={"hostname": record.hostname},
        principal=principal,
        actor_ip=client_ip(request),
        correlation_id=correlation_id(),
    )
    return AssetOut.from_record(record)
