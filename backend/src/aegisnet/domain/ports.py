"""Ports: what a use-case needs from the outside world, as Protocols and value objects.

Ports are abstract and pure, so they live in the domain: services call them, adapters
implement them, and the layering contract (entrypoints over services over adapters over
domain) holds in both directions (ADR-014). The ingest service writes through
:class:`IngestStore`; the production implementation is
:class:`aegisnet.adapters.db.ingest_store.SqlIngestStore`, tests use an in-memory fake.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Final, Generic, Protocol, TypeVar
from uuid import UUID

from aegisnet.domain.assets import AssetPatch, AssetSpec, IPAddress, IPNetwork, NetworkRecord
from aegisnet.domain.enums import (
    AlertAssetRole,
    AlertStatus,
    AssetEnvironment,
    AuditResult,
    BaselineMetric,
    DetectorRunStatus,
    EntityType,
    EventType,
    IncidentAlertSource,
    IncidentStatus,
    IngestMethod,
    IngestStatus,
    RejectReason,
    SampleRole,
    ServiceTokenRole,
    SourceType,
    TimelineEntryType,
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


# ---------------------------------------------------------------- detection (M2, FR-4/FR-5)


@dataclass(frozen=True, slots=True)
class RuleRecord:
    id: UUID
    rule_id: str
    name: str
    version: int
    enabled: bool
    base_severity: int
    window_seconds: int
    params: dict[str, Any]
    description: str
    mitre_hint: str | None
    updated_at: datetime


class RuleStore(Protocol):
    async def upsert(
        self,
        *,
        rule_id: str,
        name: str,
        version: int,
        base_severity: int,
        window_seconds: int,
        params: dict[str, Any],
        description: str,
        mitre_hint: str | None,
        now: datetime,
    ) -> RuleRecord:
        """Insert the rule or bring its row up to the code's version; ``enabled`` is the
        operator's and is never touched here."""
        ...

    async def list(self) -> tuple[RuleRecord, ...]: ...


@dataclass(frozen=True, slots=True)
class DetectorRunRecord:
    id: UUID
    rule_id: str
    window_start: datetime
    window_end: datetime
    events_examined: int
    alerts_created: int
    status: DetectorRunStatus
    error_detail: str | None
    duration_ms: int
    created_at: datetime


class DetectorRunStore(Protocol):
    async def record(
        self,
        *,
        rule_id: str,
        window_start: datetime,
        window_end: datetime,
        events_examined: int,
        alerts_created: int,
        status: DetectorRunStatus,
        error_detail: str | None,
        duration_ms: int,
        now: datetime,
    ) -> DetectorRunRecord: ...

    async def list(self, *, limit: int) -> tuple[DetectorRunRecord, ...]:
        """Newest first."""
        ...


@dataclass(frozen=True, slots=True)
class NewAlert:
    """What the sweep hands the store; ``dedup_key`` decides whether a row is created."""

    rule_id: str
    rule_version: int
    dedup_key: str
    severity: int
    confidence: float
    severity_rationale: dict[str, Any]
    entity_type: EntityType
    entity_value: str
    first_seen: datetime
    last_seen: datetime
    evidence: dict[str, Any]
    event_count: int
    samples: tuple[tuple[UUID, SampleRole], ...]
    assets: tuple[tuple[UUID, AlertAssetRole], ...]


@dataclass(frozen=True, slots=True)
class AlertRecord:
    id: UUID
    rule_id: str
    rule_version: int
    dedup_key: str
    severity: int
    confidence: float
    severity_rationale: dict[str, Any]
    entity_type: EntityType
    entity_value: str
    first_seen: datetime
    last_seen: datetime
    evidence: dict[str, Any]
    event_count: int
    status: AlertStatus
    created_at: datetime


@dataclass(frozen=True, slots=True)
class AlertDetail:
    alert: AlertRecord
    events: tuple[tuple[UUID, SampleRole], ...]
    assets: tuple[tuple[UUID, AlertAssetRole], ...]


@dataclass(frozen=True, slots=True)
class AlertFilter:
    severity_min: int | None = None
    rule_id: str | None = None
    entity_type: EntityType | None = None
    entity_value: str | None = None
    status: AlertStatus | None = None
    time_from: datetime | None = None
    time_to: datetime | None = None
    limit: int = DEFAULT_LIMIT
    cursor: str | None = None


class AlertStore(Protocol):
    async def create_many(self, alerts: Sequence[NewAlert], now: datetime) -> int:
        """Insert what is new by ``dedup_key`` with its sampled events and assets; returns
        how many rows were created. An existing key is left exactly as it was."""
        ...

    async def list(self, query: AlertFilter) -> Page[AlertRecord]: ...

    async def get(self, alert_id: UUID) -> AlertDetail | None: ...


# ---------------------------------------------------------------- incidents (M3, ADR-023)

DETAIL_TIMELINE_LIMIT: Final = 200
"""How much of a case's story one detail response carries. Past this the timeline endpoint
is the way to read it, so a case that ran for a week is bounded without being truncated."""


@dataclass(frozen=True, slots=True)
class IncidentRecord:
    id: UUID
    case_number: str
    title: str
    severity: int
    severity_rationale: dict[str, Any]
    status: IncidentStatus
    primary_asset_id: UUID | None
    correlation_key: str
    window_start: datetime
    window_end: datetime
    distinct_rule_count: int
    assigned_to: UUID | None
    closed_at: datetime | None
    closure_reason: str | None
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class NewTimelineEntry:
    """A line to append to a case's story. `alert_id` is set for `alert_fired`, which is what
    the UNIQUE constraint uses to keep a re-run from saying the same thing twice."""

    occurred_at: datetime
    entry_type: TimelineEntryType
    summary: str
    detail: dict[str, Any] = field(default_factory=dict)
    alert_id: UUID | None = None
    actor_user_id: UUID | None = None


@dataclass(frozen=True, slots=True)
class NewIncident:
    """A case to open, with the alerts that justify it. The case number is allocated by the
    store from a sequence, because two runs asking for "the next one" must not both get it."""

    correlation_key: str
    title: str
    severity: int
    severity_rationale: dict[str, Any]
    window_start: datetime
    window_end: datetime
    distinct_rule_count: int
    alert_ids: tuple[UUID, ...]
    primary_asset_id: UUID | None = None


@dataclass(frozen=True, slots=True)
class TimelineEntryRecord:
    id: UUID
    incident_id: UUID
    occurred_at: datetime
    entry_type: TimelineEntryType
    summary: str
    detail: dict[str, Any]
    alert_id: UUID | None
    actor_user_id: UUID | None
    created_at: datetime


@dataclass(frozen=True, slots=True)
class NoteRecord:
    """What an analyst wrote on a case. Never edited (ADR-024): a note is a record of what
    somebody thought at the time, and a rewritten one is a worse witness than a wrong one."""

    id: UUID
    incident_id: UUID
    author_id: UUID | None
    body: str
    created_at: datetime


@dataclass(frozen=True, slots=True)
class IncidentDetail:
    incident: IncidentRecord
    alert_ids: tuple[UUID, ...]
    timeline: tuple[TimelineEntryRecord, ...]
    alerts: tuple[AlertRecord, ...] = ()
    """The linked alerts themselves, so opening a case is one call rather than one per alert."""
    timeline_truncated: bool = False
    """The timeline here is the newest ``DETAIL_TIMELINE_LIMIT`` entries. When this is true the
    case has more of a story than the detail carries, and the timeline endpoint has the rest."""


@dataclass(frozen=True, slots=True)
class IncidentFilter:
    status: IncidentStatus | None = None
    open_only: bool = False
    severity_min: int | None = None
    correlation_key: str | None = None
    limit: int = DEFAULT_LIMIT
    cursor: str | None = None


class IncidentStore(Protocol):
    async def open_case(
        self,
        incident: NewIncident,
        entries: Sequence[NewTimelineEntry],
        *,
        now: datetime,
        source: IncidentAlertSource = IncidentAlertSource.correlation_engine,
    ) -> IncidentRecord:
        """Allocate a case number, create the case, link its alerts and write its story."""
        ...

    async def newest_open_for_key(self, correlation_key: str) -> IncidentRecord | None:
        """The most recent case for this entity that is still open, or ``None``. A closed case
        is never returned: it must not absorb new alerts (ADR-023)."""
        ...

    async def newest_closed_for_key(self, correlation_key: str) -> IncidentRecord | None:
        """The most recent *closed* case for this entity, or ``None``. Never extended — a new
        case is opened beside it and names it, so the judgement somebody already made stays
        where they left it (ADR-023)."""
        ...

    async def extend(
        self,
        incident_id: UUID,
        alert_ids: Sequence[UUID],
        entries: Sequence[NewTimelineEntry],
        *,
        severity: int,
        severity_rationale: dict[str, Any],
        title: str,
        window_end: datetime,
        distinct_rule_count: int,
        now: datetime,
        source: IncidentAlertSource = IncidentAlertSource.correlation_engine,
    ) -> int:
        """Add alerts to an open case and grow it; returns how many links were new."""
        ...

    async def already_linked(self, alert_ids: Sequence[UUID]) -> set[UUID]:
        """Of these alerts, the ones already in some case. One alert belongs to one case."""
        ...

    async def set_status(
        self,
        incident_id: UUID,
        *,
        expected: IncidentStatus,
        target: IncidentStatus,
        closure_reason: str | None,
        entry: NewTimelineEntry,
        now: datetime,
    ) -> IncidentRecord | None:
        """Move a case from ``expected`` to ``target`` and write ``entry`` in the same
        transaction, or return ``None`` because the case was no longer in ``expected``.

        The expected status is part of the write rather than something the caller checked
        first: two analysts deciding at the same moment is the ordinary case in a shift
        handover, and the one who loses must be told, not silently overwritten (T-2.3).
        """
        ...

    async def add_note(
        self,
        incident_id: UUID,
        *,
        body: str,
        author_id: UUID | None,
        entry: NewTimelineEntry,
        now: datetime,
    ) -> NoteRecord | None:
        """Append a note and its timeline line together; ``None`` when there is no such case."""
        ...

    async def list_notes(
        self, incident_id: UUID, *, limit: int, cursor: str | None
    ) -> Page[NoteRecord]:
        """Newest first, keyset-paginated."""
        ...

    async def list_timeline(
        self, incident_id: UUID, *, limit: int, cursor: str | None
    ) -> Page[TimelineEntryRecord]:
        """The whole story in the order it happened, keyset-paginated so a long case stays
        reachable past whatever the detail response carries."""
        ...

    async def list(self, query: IncidentFilter) -> Page[IncidentRecord]: ...

    async def get(
        self, incident_id: UUID, *, timeline_limit: int = DETAIL_TIMELINE_LIMIT
    ) -> IncidentDetail | None: ...

    async def get_by_case_number(
        self, case_number: str, *, timeline_limit: int = DETAIL_TIMELINE_LIMIT
    ) -> IncidentDetail | None: ...


@dataclass(frozen=True, slots=True)
class BaselineRecord:
    id: UUID
    asset_id: UUID
    metric: BaselineMetric
    window_days: int
    mean: float
    stddev: float
    p95: float
    sample_count: int
    computed_at: datetime


class BaselineStore(Protocol):
    async def upsert(
        self,
        *,
        asset_id: UUID,
        metric: BaselineMetric,
        window_days: int,
        mean: float,
        stddev: float,
        p95: float,
        sample_count: int,
        now: datetime,
    ) -> BaselineRecord: ...

    async def list(self, *, metric: BaselineMetric | None = None) -> tuple[BaselineRecord, ...]: ...


class OutboundHistoryStore(Protocol):
    async def hourly_outbound_bytes(
        self, networks: Sequence[IPNetwork], start: datetime, end: datetime
    ) -> tuple[tuple[datetime, int], ...]:
        """``(hour, bytes_toserver)`` per hour for flows whose source lies in any of
        ``networks`` and whose destination is not internal, oldest first; hours with no
        such flow are omitted."""
        ...


class EventWindowStore(Protocol):
    async def load(
        self, start: datetime, end: datetime, *, max_events: int
    ) -> tuple[tuple[EventRow, ...], bool]:
        """Events with ``start <= event_time < end`` ordered by ``(event_time, id)``, at most
        ``max_events`` of them; the flag says whether the cap cut the window short."""
        ...

    async def batch_span(self, batch_id: UUID) -> tuple[datetime, datetime] | None:
        """``(min, max)`` event time of the batch's stored events, ``None`` when it stored
        nothing; the post-ingest sweep covers exactly this span (ADR-020)."""
        ...


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
