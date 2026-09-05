"""Request and response DTOs for the Milestone 1 API (``docs/api-milestone-1.md``).

Every inbound body forbids unknown fields. Response models are built from the domain
value objects by the ``from_*`` constructors, so a route never hand-assembles a dict.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Final, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from aegisnet.domain.assets import MAX_BULK, AssetSpec
from aegisnet.domain.enums import (
    AssetEnvironment,
    AuditResult,
    EventType,
    IngestMethod,
    IngestStatus,
    RejectReason,
    SourceType,
)
from aegisnet.domain.ports import (
    AssetRecord,
    AuditRow,
    BatchSummary,
    EventRow,
    EventStats,
    Page,
    RejectRow,
    ResolvedAsset,
    UserRecord,
)

SOURCE_LABEL: Final = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
DATASET_ID: Final = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")


class Inbound(BaseModel):
    model_config = ConfigDict(extra="forbid")


# ---------------------------------------------------------------- auth


class LoginRequest(Inbound):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=128)


class TokenResponse(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"
    expires_in: int


class UserOut(BaseModel):
    id: UUID
    email: str
    display_name: str
    role: str

    @classmethod
    def from_record(cls, user: UserRecord) -> UserOut:
        return cls(
            id=user.id, email=user.email, display_name=user.display_name, role=user.role.value
        )


# ---------------------------------------------------------------- ingest


class ImportRequest(Inbound):
    dataset_id: str = Field(pattern=DATASET_ID.pattern)
    source_label: str = Field(pattern=SOURCE_LABEL.pattern)


class CountsOut(BaseModel):
    received: int
    stored: int
    duplicate: int
    rejected: int


class BatchOut(BaseModel):
    batch_id: UUID
    status: IngestStatus
    source_label: str
    dataset_id: str | None
    counts: CountsOut
    started_at: datetime
    finished_at: datetime | None

    @classmethod
    def from_summary(cls, summary: BatchSummary) -> BatchOut:
        return cls(
            batch_id=summary.batch_id,
            status=summary.status,
            source_label=summary.source_label,
            dataset_id=summary.dataset_id,
            counts=CountsOut(
                received=summary.counts.received,
                stored=summary.counts.stored,
                duplicate=summary.counts.duplicate,
                rejected=summary.counts.rejected,
            ),
            started_at=summary.started_at,
            finished_at=summary.finished_at,
        )


class IngestAccepted(BaseModel):
    batch_id: UUID
    status: Literal["received"] = "received"
    bytes_received: int
    accepted_at: datetime
    poll_url: str


class BatchPage(BaseModel):
    items: list[BatchOut]
    next_cursor: str | None

    @classmethod
    def from_page(cls, page: Page[BatchSummary]) -> BatchPage:
        return cls(
            items=[BatchOut.from_summary(s) for s in page.items], next_cursor=page.next_cursor
        )


class RejectOut(BaseModel):
    line_number: int
    reason_code: RejectReason
    detail: str
    raw_excerpt: str | None
    created_at: datetime

    @classmethod
    def from_row(cls, row: RejectRow) -> RejectOut:
        return cls(
            line_number=row.line_number,
            reason_code=row.reason,
            detail=row.detail,
            raw_excerpt=row.raw_excerpt,
            created_at=row.created_at,
        )


class RejectPage(BaseModel):
    items: list[RejectOut]
    next_cursor: str | None


# ---------------------------------------------------------------- assets


class NetworkOut(BaseModel):
    id: UUID
    cidr: str
    is_primary: bool


class AssetOut(BaseModel):
    id: UUID
    hostname: str | None
    environment: AssetEnvironment
    owner: str | None
    criticality: int
    tags: list[str]
    description: str | None
    is_active: bool
    created_at: datetime
    updated_at: datetime
    networks: list[NetworkOut]

    @classmethod
    def from_record(cls, record: AssetRecord) -> AssetOut:
        return cls(
            id=record.id,
            hostname=record.hostname,
            environment=record.environment,
            owner=record.owner,
            criticality=record.criticality,
            tags=list(record.tags),
            description=record.description,
            is_active=record.is_active,
            created_at=record.created_at,
            updated_at=record.updated_at,
            networks=[
                NetworkOut(id=n.id, cidr=str(n.cidr), is_primary=n.is_primary)
                for n in record.networks
            ],
        )


class AssetPage(BaseModel):
    items: list[AssetOut]
    next_cursor: str | None

    @classmethod
    def from_page(cls, page: Page[AssetRecord]) -> AssetPage:
        return cls(
            items=[AssetOut.from_record(a) for a in page.items], next_cursor=page.next_cursor
        )


class BulkAssetsRequest(Inbound):
    assets: list[AssetSpec] = Field(min_length=1, max_length=MAX_BULK)


class BulkAssetsOut(BaseModel):
    created: list[AssetOut]


class ResolveOut(BaseModel):
    matched: bool
    ip: str
    asset: AssetOut | None = None
    matched_cidr: str | None = None

    @classmethod
    def from_resolution(cls, ip: str, resolved: ResolvedAsset | None) -> ResolveOut:
        if resolved is None:
            return cls(matched=False, ip=ip)
        return cls(
            matched=True,
            ip=ip,
            asset=AssetOut.from_record(resolved.asset),
            matched_cidr=str(resolved.matched_cidr),
        )


# ---------------------------------------------------------------- events


class EventOut(BaseModel):
    id: UUID
    batch_id: UUID
    event_time: datetime
    ingested_at: datetime
    event_type: EventType
    flow_id: int | None
    src_ip: str | None
    dest_ip: str | None
    src_port: int | None
    dest_port: int | None
    proto: str | None
    app_proto: str | None
    bytes_toserver: int | None
    bytes_toclient: int | None
    pkts_toserver: int | None
    pkts_toclient: int | None
    dns_query: str | None
    dns_rrtype: str | None
    dns_rcode: str | None
    http_host: str | None
    http_url_path: str | None
    sig_signature: str | None
    sig_category: str | None
    sig_signature_id: int | None
    sig_severity: int | None
    payload: dict[str, Any] | None = None

    @classmethod
    def from_row(cls, row: EventRow) -> EventOut:
        return cls(
            id=row.id,
            batch_id=row.batch_id,
            event_time=row.event_time,
            ingested_at=row.ingested_at,
            event_type=row.event_type,
            flow_id=row.flow_id,
            src_ip=None if row.src_ip is None else str(row.src_ip),
            dest_ip=None if row.dest_ip is None else str(row.dest_ip),
            src_port=row.src_port,
            dest_port=row.dest_port,
            proto=row.proto,
            app_proto=row.app_proto,
            bytes_toserver=row.bytes_toserver,
            bytes_toclient=row.bytes_toclient,
            pkts_toserver=row.pkts_toserver,
            pkts_toclient=row.pkts_toclient,
            dns_query=row.dns_query,
            dns_rrtype=row.dns_rrtype,
            dns_rcode=row.dns_rcode,
            http_host=row.http_host,
            http_url_path=row.http_url_path,
            sig_signature=row.sig_signature,
            sig_category=row.sig_category,
            sig_signature_id=row.sig_signature_id,
            sig_severity=row.sig_severity,
            payload=row.payload,
        )


class EventPage(BaseModel):
    items: list[EventOut]
    next_cursor: str | None


class HourBucket(BaseModel):
    hour: datetime
    count: int


class StatsOut(BaseModel):
    total: int
    by_type: dict[str, int]
    by_hour: list[HourBucket]

    @classmethod
    def from_stats(cls, stats: EventStats) -> StatsOut:
        return cls(
            total=stats.total,
            by_type=dict(stats.by_type),
            by_hour=[HourBucket(hour=moment, count=count) for moment, count in stats.by_hour],
        )


# ---------------------------------------------------------------- audit


class AuditOut(BaseModel):
    id: int
    occurred_at: datetime
    action: str
    target_type: str
    target_id: str | None
    result: AuditResult
    detail: dict[str, Any]
    actor_user_id: UUID | None
    actor_token_id: UUID | None
    actor_ip: str | None
    correlation_id: UUID | None

    @classmethod
    def from_row(cls, row: AuditRow) -> AuditOut:
        entry = row.entry
        return cls(
            id=row.id,
            occurred_at=entry.occurred_at,
            action=entry.action,
            target_type=entry.target_type,
            target_id=entry.target_id,
            result=entry.result,
            detail=entry.detail,
            actor_user_id=entry.actor_user_id,
            actor_token_id=entry.actor_token_id,
            actor_ip=None if entry.actor_ip is None else str(entry.actor_ip),
            correlation_id=entry.correlation_id,
        )


class AuditPage(BaseModel):
    items: list[AuditOut]
    next_cursor: str | None


__all__ = [
    "AssetOut",
    "AssetPage",
    "AuditOut",
    "AuditPage",
    "BatchOut",
    "BatchPage",
    "BulkAssetsOut",
    "BulkAssetsRequest",
    "EventOut",
    "EventPage",
    "ImportRequest",
    "IngestAccepted",
    "IngestMethod",
    "LoginRequest",
    "RejectOut",
    "RejectPage",
    "ResolveOut",
    "SourceType",
    "StatsOut",
    "TokenResponse",
    "UserOut",
]
