"""Ingest routes (FR-1): NDJSON or multipart upload, registry import, batch reads.

The body is streamed to the spool under a hard byte cap before anything parses it
(T-1.4); ``sync`` mode then runs the ingest service inline for at most
``INGEST_SYNC_MAX_LINES`` lines, ``async`` mode opens the batch row and hands the spool
name to the worker (TB-5: ids only). Every request is rate limited per token by count and
by bytes per hour, and every batch creation is audited (T-1.8).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, status
from fastapi.responses import JSONResponse
from starlette.datastructures import UploadFile

from aegisnet.adapters.files.spool import SpoolTooLargeError
from aegisnet.api.deps import (
    AppServices,
    client_ip,
    correlation_id,
    enforce_limit,
    rate_limit,
    require,
    services,
)
from aegisnet.api.errors import PayloadTooLargeError, ValidationFailedError
from aegisnet.api.schemas import (
    SOURCE_LABEL,
    BatchOut,
    BatchPage,
    ImportRequest,
    IngestAccepted,
    RejectOut,
    RejectPage,
)
from aegisnet.domain.auth import Permission, Principal, PrincipalKind
from aegisnet.domain.enums import AuditResult, IngestMethod, IngestStatus, SourceType
from aegisnet.domain.pagination import DEFAULT_LIMIT, MAX_LIMIT
from aegisnet.domain.ports import BatchFilter, BatchProvenance
from aegisnet.services.ingest_service import provenance_for

router = APIRouter(prefix="/api/v1/ingest", tags=["ingest"])

UPLOAD_CHUNK = 64 * 1024


def _actor_ids(principal: Principal) -> tuple[UUID | None, UUID | None]:
    if principal.kind is PrincipalKind.user:
        return principal.id, None
    return None, principal.id


async def _file_chunks(upload: UploadFile) -> AsyncIterator[bytes]:
    while chunk := await upload.read(UPLOAD_CHUNK):
        yield chunk


async def _audit_refusal(
    svc: AppServices, principal: Principal, request: Request, reason: str, **detail: object
) -> None:
    """A refused upload leaves a trail too (api-milestone-1: oversized input is audited)."""
    await svc.audit.record(
        "ingest.refused",
        target_type="ingest",
        result=AuditResult.denied,
        detail={"reason": reason, **detail},
        principal=principal,
        actor_ip=client_ip(request),
        correlation_id=correlation_id(),
    )


@router.post(
    "/eve",
    summary="Ingest Suricata EVE NDJSON (body or multipart file)",
    responses={200: {"model": BatchOut}, 202: {"model": IngestAccepted}},
)
async def ingest_eve(
    request: Request,
    svc: Annotated[AppServices, Depends(services)],
    principal: Annotated[Principal, Depends(require(Permission.ingest_write))],
    source_label: Annotated[str, Query(pattern=SOURCE_LABEL.pattern)],
    mode: Literal["sync", "async"] = "async",
) -> JSONResponse:
    settings = svc.settings
    await enforce_limit(
        svc.limiter,
        "ingest",
        principal.subject,
        limit=settings.rate_limit_ingest_per_min,
        window_seconds=60,
        fail_open=False,
    )
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > settings.ingest_max_body_bytes:
        await _audit_refusal(svc, principal, request, "body_too_large", declared=int(declared))
        raise PayloadTooLargeError(f"body exceeds {settings.ingest_max_body_bytes} bytes")

    content_type = request.headers.get("content-type", "")
    try:
        if content_type.startswith("multipart/form-data"):
            if not declared.isdigit():
                raise ValidationFailedError("content-length", "required for multipart uploads")
            form = await request.form(max_files=1, max_fields=4)
            upload = form.get("file")
            if not isinstance(upload, UploadFile):
                raise ValidationFailedError("file", "a multipart part named 'file' is required")
            method = IngestMethod.api_file
            spooled = await svc.spool.write(
                _file_chunks(upload), max_bytes=settings.ingest_max_body_bytes
            )
        else:
            method = IngestMethod.api_ndjson
            spooled = await svc.spool.write(
                request.stream(), max_bytes=settings.ingest_max_body_bytes
            )
    except SpoolTooLargeError:
        await _audit_refusal(svc, principal, request, "body_too_large")
        raise

    try:
        await enforce_limit(
            svc.limiter,
            "ingest_bytes",
            principal.subject,
            limit=settings.rate_limit_ingest_bytes_per_hour,
            window_seconds=3600,
            cost=max(spooled.size, 1),
            fail_open=False,
        )
    except Exception:
        svc.spool.remove(spooled.name)
        raise

    actor_user_id, actor_token_id = _actor_ids(principal)
    provenance = BatchProvenance(
        source_type=SourceType.suricata_eve,
        source_label=source_label,
        ingest_method=method,
        actor_user_id=actor_user_id,
        actor_token_id=actor_token_id,
    )
    ip = client_ip(request)

    if mode == "sync":
        cap = settings.ingest_sync_max_lines
        if svc.spool.count_lines(spooled.name, stop_above=cap) > cap:
            svc.spool.remove(spooled.name)
            await _audit_refusal(svc, principal, request, "sync_lines_exceeded", cap=cap)
            raise PayloadTooLargeError(f"sync mode accepts at most {cap} lines; use mode=async")
        try:
            with svc.spool.open(spooled.name).open("rb") as handle:
                summary = await svc.ingest.ingest(handle, provenance)
        finally:
            svc.spool.remove(spooled.name)
        await svc.audit.record(
            "ingest.batch_created",
            target_type="ingest_batch",
            target_id=str(summary.batch_id),
            detail={
                "mode": "sync",
                "method": method.value,
                "source_label": source_label,
                "bytes": spooled.size,
                "received": summary.counts.received,
                "stored": summary.counts.stored,
                "duplicate": summary.counts.duplicate,
                "rejected": summary.counts.rejected,
                "status": summary.status.value,
            },
            principal=principal,
            actor_ip=ip,
            correlation_id=correlation_id(),
        )
        return JSONResponse(BatchOut.from_summary(summary).model_dump(mode="json"))

    batch_id = await svc.ingest.open_batch(provenance)
    try:
        await svc.enqueue_upload(batch_id, spooled.name, source_label)
    except Exception:
        svc.spool.remove(spooled.name)
        raise
    await svc.audit.record(
        "ingest.batch_created",
        target_type="ingest_batch",
        target_id=str(batch_id),
        detail={
            "mode": "async",
            "method": method.value,
            "source_label": source_label,
            "bytes": spooled.size,
        },
        principal=principal,
        actor_ip=ip,
        correlation_id=correlation_id(),
    )
    accepted = IngestAccepted(
        batch_id=batch_id,
        bytes_received=spooled.size,
        accepted_at=datetime.now(tz=UTC),
        poll_url=f"/api/v1/ingest/batches/{batch_id}",
    )
    return JSONResponse(accepted.model_dump(mode="json"), status_code=status.HTTP_202_ACCEPTED)


@router.post(
    "/import",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=IngestAccepted,
    summary="Import a registered dataset (no path is ever accepted)",
    dependencies=[Depends(rate_limit("default"))],
)
async def import_dataset(
    body: ImportRequest,
    request: Request,
    svc: Annotated[AppServices, Depends(services)],
    principal: Annotated[Principal, Depends(require(Permission.ingest_import))],
) -> IngestAccepted:
    resolved = svc.ingest.resolve(svc.settings.samples_dir, body.dataset_id)
    actor_user_id, actor_token_id = _actor_ids(principal)
    provenance = provenance_for(
        resolved, body.source_label, actor_user_id=actor_user_id, actor_token_id=actor_token_id
    )
    batch_id = await svc.ingest.open_batch(provenance)
    await svc.enqueue_import(batch_id, body.dataset_id, body.source_label)
    await svc.audit.record(
        "ingest.import_requested",
        target_type="ingest_batch",
        target_id=str(batch_id),
        detail={"dataset_id": body.dataset_id, "source_label": body.source_label},
        principal=principal,
        actor_ip=client_ip(request),
        correlation_id=correlation_id(),
    )
    return IngestAccepted(
        batch_id=batch_id,
        bytes_received=resolved.path.stat().st_size,
        accepted_at=datetime.now(tz=UTC),
        poll_url=f"/api/v1/ingest/batches/{batch_id}",
    )


@router.get(
    "/batches",
    response_model=BatchPage,
    summary="List batches, newest first",
    dependencies=[Depends(require(Permission.ingest_read)), Depends(rate_limit("read"))],
)
async def list_batches(
    svc: Annotated[AppServices, Depends(services)],
    batch_status: Annotated[IngestStatus | None, Query(alias="status")] = None,
    source_label: Annotated[str | None, Query(pattern=SOURCE_LABEL.pattern)] = None,
    time_from: Annotated[datetime | None, Query(alias="from")] = None,
    time_to: Annotated[datetime | None, Query(alias="to")] = None,
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = DEFAULT_LIMIT,
    cursor: str | None = None,
) -> BatchPage:
    page = await svc.ingest.list_batches(
        BatchFilter(
            status=batch_status,
            source_label=source_label,
            time_from=time_from,
            time_to=time_to,
            limit=limit,
            cursor=cursor,
        )
    )
    return BatchPage.from_page(page)


@router.get(
    "/batches/{batch_id}",
    response_model=BatchOut,
    summary="One batch",
    dependencies=[Depends(require(Permission.ingest_read)), Depends(rate_limit("read"))],
)
async def get_batch(batch_id: UUID, svc: Annotated[AppServices, Depends(services)]) -> BatchOut:
    from aegisnet.services.ingest_service import BatchNotFoundError

    summary = await svc.ingest.get_batch(batch_id)
    if summary is None:
        raise BatchNotFoundError("unknown batch")
    return BatchOut.from_summary(summary)


@router.get(
    "/batches/{batch_id}/rejects",
    response_model=RejectPage,
    summary="Rejected lines of a batch",
    dependencies=[Depends(require(Permission.ingest_read)), Depends(rate_limit("read"))],
)
async def list_rejects(
    batch_id: UUID,
    svc: Annotated[AppServices, Depends(services)],
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = DEFAULT_LIMIT,
    cursor: str | None = None,
) -> RejectPage:
    page = await svc.ingest.list_rejects(batch_id, limit=limit, cursor=cursor)
    return RejectPage(
        items=[RejectOut.from_row(r) for r in page.items], next_cursor=page.next_cursor
    )
