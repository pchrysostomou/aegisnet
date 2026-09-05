"""Ports: what a use-case needs from the outside world, as Protocols and value objects.

Ports are abstract and pure, so they live in the domain: services call them, adapters
implement them, and the layering contract (entrypoints over services over adapters over
domain) holds in both directions (ADR-014). The ingest service writes through
:class:`IngestStore`; the production implementation is
:class:`aegisnet.adapters.db.ingest_store.SqlIngestStore`, tests use an in-memory fake.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Generic, Protocol, TypeVar
from uuid import UUID

from aegisnet.domain.assets import AssetPatch, AssetSpec, IPAddress, IPNetwork, NetworkRecord
from aegisnet.domain.enums import (
    AssetEnvironment,
    AuditResult,
    EventType,
    IngestMethod,
    IngestStatus,
    RejectReason,
    ServiceTokenRole,
    SourceType,
    UserRole,
)
from aegisnet.domain.models import NormalizedEvent, Reject
from aegisnet.domain.pagination import DEFAULT_LIMIT

T = TypeVar("T")


@dataclass(frozen=True)
class Page(Generic[T]):
    """One page of a keyset-paginated list; ``next_cursor`` is ``None`` on the last page."""

    items: tuple[T, ...]
    next_cursor: str | None = None


@dataclass(frozen=True, slots=True)
class BatchProvenance:
    """Who loaded what, from where (FR-1.6, T-1.8). Actor ids arrive with Chunk 6."""

    source_type: SourceType
    source_label: str
    ingest_method: IngestMethod
    dataset_id: str | None = None
    dataset_licence: str | None = None
    dataset_citation: str | None = None
    actor_user_id: UUID | None = None
    actor_token_id: UUID | None = None


@dataclass(frozen=True, slots=True)
class BatchCounts:
    received: int = 0
    stored: int = 0
    duplicate: int = 0
    rejected: int = 0


@dataclass(frozen=True, slots=True)
class BatchSummary:
    batch_id: UUID
    status: IngestStatus
    source_label: str
    dataset_id: str | None
    counts: BatchCounts
    started_at: datetime
    finished_at: datetime | None


@dataclass(frozen=True, slots=True)
class RejectedLine:
    line_number: int
    reject: Reject


class IngestStore(Protocol):
    """Persistence for one ingest batch. Every method is one short transaction."""

    async def open_batch(self, provenance: BatchProvenance, started_at: datetime) -> UUID: ...

    async def mark_normalizing(self, batch_id: UUID) -> None: ...

    async def store_events(
        self, batch_id: UUID, events: Sequence[NormalizedEvent], ingested_at: datetime
    ) -> int:
        """Insert, skipping any ``event_hash`` already present. Returns how many were new."""
        ...

    async def store_rejects(self, batch_id: UUID, rejects: Sequence[RejectedLine]) -> None: ...

    async def finish_batch(
        self, batch_id: UUID, status: IngestStatus, counts: BatchCounts, finished_at: datetime
    ) -> None: ...

    async def get_batch(self, batch_id: UUID) -> BatchSummary | None: ...

    async def list_batches(self, query: BatchFilter) -> Page[BatchSummary]: ...

    async def list_rejects(
        self, batch_id: UUID, *, limit: int, cursor: str | None
    ) -> Page[RejectRow]: ...


@dataclass(frozen=True, slots=True)
class BatchFilter:
    status: IngestStatus | None = None
    source_label: str | None = None
    time_from: datetime | None = None
    time_to: datetime | None = None
    limit: int = DEFAULT_LIMIT
    cursor: str | None = None


@dataclass(frozen=True, slots=True)
class RejectRow:
    line_number: int
    reason: RejectReason
    detail: str
    raw_excerpt: str | None
    created_at: datetime


# ---------------------------------------------------------------- assets (FR-3)


@dataclass(frozen=True, slots=True)
class NetworkView:
    id: UUID
    cidr: IPNetwork
    is_primary: bool


@dataclass(frozen=True, slots=True)
class AssetRecord:
    id: UUID
    hostname: str | None
    environment: AssetEnvironment
    owner: str | None
    criticality: int
    tags: tuple[str, ...]
    description: str | None
    is_active: bool
    created_at: datetime
    updated_at: datetime
    networks: tuple[NetworkView, ...]


@dataclass(frozen=True, slots=True)
class AssetFilter:
    environment: AssetEnvironment | None = None
    criticality_min: int | None = None
    tag: str | None = None
    q: str | None = None
    include_inactive: bool = False
    limit: int = DEFAULT_LIMIT
    cursor: str | None = None


@dataclass(frozen=True, slots=True)
class ResolvedAsset:
    asset: AssetRecord
    matched_cidr: IPNetwork


class AssetStore(Protocol):
    async def create(self, spec: AssetSpec, now: datetime) -> AssetRecord: ...

    async def create_many(
        self, specs: Sequence[AssetSpec], now: datetime
    ) -> tuple[AssetRecord, ...]:
        """All or nothing."""
        ...

    async def get(self, asset_id: UUID) -> AssetRecord | None: ...

    async def get_by_hostname(self, hostname: str) -> AssetRecord | None: ...

    async def list(self, query: AssetFilter) -> Page[AssetRecord]: ...

    async def update(
        self, asset_id: UUID, patch: AssetPatch, now: datetime
    ) -> AssetRecord | None: ...

    async def deactivate(self, asset_id: UUID, now: datetime) -> AssetRecord | None: ...

    async def networks(self, *, active_only: bool = True) -> tuple[NetworkRecord, ...]: ...

    async def resolve(self, address: IPAddress) -> ResolvedAsset | None: ...


# ---------------------------------------------------------------- events, read-only (M1 API)


@dataclass(frozen=True, slots=True)
class EventQuery:
    time_from: datetime
    time_to: datetime
    event_types: tuple[EventType, ...] = ()
    src_ip: IPAddress | IPNetwork | None = None
    dest_ip: IPAddress | IPNetwork | None = None
    dest_ports: tuple[int, ...] = ()
    flow_id: int | None = None
    batch_id: UUID | None = None
    asset_id: UUID | None = None
    limit: int = DEFAULT_LIMIT
    cursor: str | None = None
    include_payload: bool = False


@dataclass(frozen=True, slots=True)
class EventRow:
    id: UUID
    batch_id: UUID
    event_time: datetime
    ingested_at: datetime
    event_type: EventType
    flow_id: int | None
    src_ip: IPAddress | None
    dest_ip: IPAddress | None
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
    payload: dict[str, Any] | None


@dataclass(frozen=True, slots=True)
class EventStats:
    total: int
    by_type: tuple[tuple[str, int], ...]
    by_hour: tuple[tuple[datetime, int], ...]


class EventReadStore(Protocol):
    async def query(self, query: EventQuery) -> Page[EventRow]: ...

    async def get(self, event_id: UUID, *, include_payload: bool) -> EventRow | None: ...

    async def stats(self, query: EventQuery) -> EventStats: ...


# ---------------------------------------------------------------- users, tokens (FR-10)


@dataclass(frozen=True, slots=True)
class UserRecord:
    id: UUID
    email: str
    display_name: str
    password_hash: str
    role: UserRole
    is_active: bool
    failed_login_count: int
    locked_until: datetime | None
    last_login_at: datetime | None
    created_at: datetime


class UserStore(Protocol):
    async def create(
        self, email: str, display_name: str, password_hash: str, role: UserRole, now: datetime
    ) -> UserRecord: ...

    async def get(self, user_id: UUID) -> UserRecord | None: ...

    async def get_by_email(self, email: str) -> UserRecord | None: ...

    async def record_failure(
        self, user_id: UUID, now: datetime, *, lock_until: datetime | None
    ) -> None:
        """Increment the failure count; when ``lock_until`` is given, lock the account."""
        ...

    async def record_success(self, user_id: UUID, now: datetime) -> None:
        """Reset the failure count, clear any lock, stamp ``last_login_at``."""
        ...

    async def list(self) -> tuple[UserRecord, ...]: ...


@dataclass(frozen=True, slots=True)
class RefreshTokenRecord:
    id: UUID
    user_id: UUID
    token_hash: bytes
    issued_at: datetime
    expires_at: datetime
    rotated_to: UUID | None
    revoked_at: datetime | None


class RefreshTokenStore(Protocol):
    async def create(
        self,
        user_id: UUID,
        token_hash: bytes,
        issued_at: datetime,
        expires_at: datetime,
        user_agent_hash: bytes | None,
        ip_hash: bytes | None,
    ) -> RefreshTokenRecord: ...

    async def get_by_hash(self, token_hash: bytes) -> RefreshTokenRecord | None: ...

    async def rotate(self, old_id: UUID, new_id: UUID, now: datetime) -> None:
        """Mark ``old_id`` rotated to ``new_id`` and revoked."""
        ...

    async def revoke_chain(self, token_id: UUID, now: datetime) -> int:
        """Revoke ``token_id`` and every token it was rotated into. Returns how many."""
        ...


@dataclass(frozen=True, slots=True)
class ServiceTokenRecord:
    id: UUID
    name: str
    token_hash: bytes
    role: ServiceTokenRole
    created_by: UUID | None
    expires_at: datetime
    revoked_at: datetime | None
    last_used_at: datetime | None
    created_at: datetime


class ServiceTokenStore(Protocol):
    async def create(
        self,
        name: str,
        token_hash: bytes,
        role: ServiceTokenRole,
        created_by: UUID | None,
        expires_at: datetime,
        now: datetime,
    ) -> ServiceTokenRecord: ...

    async def get_by_hash(self, token_hash: bytes) -> ServiceTokenRecord | None: ...

    async def touch(self, token_id: UUID, now: datetime) -> None: ...

    async def revoke(self, token_id: UUID, now: datetime) -> ServiceTokenRecord | None: ...

    async def list(self) -> tuple[ServiceTokenRecord, ...]: ...


# ---------------------------------------------------------------- audit (FR-10.3, T-2.5)


@dataclass(frozen=True, slots=True)
class AuditEntry:
    occurred_at: datetime
    action: str
    target_type: str
    target_id: str | None
    result: AuditResult
    detail: dict[str, Any]
    actor_user_id: UUID | None = None
    actor_token_id: UUID | None = None
    actor_ip: IPAddress | None = None
    correlation_id: UUID | None = None


@dataclass(frozen=True, slots=True)
class AuditRow:
    id: int
    entry: AuditEntry


@dataclass(frozen=True, slots=True)
class AuditFilter:
    action: str | None = None
    actor_user_id: UUID | None = None
    result: AuditResult | None = None
    time_from: datetime | None = None
    time_to: datetime | None = None
    limit: int = DEFAULT_LIMIT
    cursor: str | None = None


class AuditSink(Protocol):
    async def write(self, entry: AuditEntry) -> None:
        """Append one row in its own short transaction, so a rolled-back request still
        leaves its audit trail."""
        ...


class AuditReadStore(Protocol):
    async def list(self, query: AuditFilter) -> Page[AuditRow]: ...


# ---------------------------------------------------------------- rate limits, denylist


@dataclass(frozen=True, slots=True)
class RateLimitDecision:
    allowed: bool
    remaining: int
    retry_after: int
    """Seconds until the window resets; meaningful when ``allowed`` is false."""


class RateLimiter(Protocol):
    async def hit(
        self, name: str, subject: str, *, limit: int, window_seconds: int, cost: int = 1
    ) -> RateLimitDecision: ...


class TokenDenylist(Protocol):
    async def add(self, token_id: str, ttl_seconds: int) -> None: ...

    async def contains(self, token_id: str) -> bool: ...
