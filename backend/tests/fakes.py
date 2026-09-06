"""In-memory implementations of the ports, and a services factory that wires them into
the real FastAPI app. The routes under test are the production routes; only the edges
(database, Redis, queue, spool directory) are replaced."""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from argon2 import PasswordHasher
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncEngine

from aegisnet.adapters.db.auth_store import EmailTakenError
from aegisnet.adapters.files.spool import Spool
from aegisnet.adapters.perplexity import PerplexityClient
from aegisnet.api.deps import AppServices
from aegisnet.config import Settings
from aegisnet.domain.assets import (
    AssetPatch,
    AssetSpec,
    IPAddress,
    IPNetwork,
    NetworkRecord,
    resolve_ip,
)
from aegisnet.domain.detectors.addresses import is_internal
from aegisnet.domain.enums import (
    AlertAssetRole,
    AlertStatus,
    BaselineMetric,
    DetectorRunStatus,
    EventType,
    IncidentAlertSource,
    IncidentStatus,
    IngestStatus,
    SampleRole,
    ServiceTokenRole,
    UserRole,
)
from aegisnet.domain.incidents import case_number, is_closed
from aegisnet.domain.models import NormalizedEvent
from aegisnet.domain.pagination import decode_time_id, encode_time_id
from aegisnet.domain.ports import (
    DETAIL_TIMELINE_LIMIT,
    AlertDetail,
    AlertFilter,
    AlertRecord,
    AssetFilter,
    AssetRecord,
    AuditEntry,
    AuditFilter,
    AuditRow,
    BaselineRecord,
    BatchCounts,
    BatchFilter,
    BatchProvenance,
    BatchSummary,
    BriefRecord,
    DetectorRunRecord,
    EventQuery,
    EventRow,
    EventStats,
    IncidentDetail,
    IncidentFilter,
    IncidentRecord,
    NetworkView,
    NewAlert,
    NewBrief,
    NewIncident,
    NewTimelineEntry,
    NoteRecord,
    Page,
    RateLimitDecision,
    RefreshTokenRecord,
    RejectedLine,
    RejectRow,
    ResolvedAsset,
    RuleRecord,
    ServiceTokenRecord,
    TimelineEntryRecord,
    UserRecord,
)
from aegisnet.services.asset_service import AssetService
from aegisnet.services.audit_service import AuditReadService, AuditService
from aegisnet.services.auth_service import AuthPolicy, AuthService
from aegisnet.services.baseline_service import BaselineService
from aegisnet.services.brief_service import BriefService
from aegisnet.services.detection_service import DetectionService
from aegisnet.services.event_read_service import EventReadService
from aegisnet.services.incident_service import IncidentService
from aegisnet.services.ingest_service import IngestService, limits_from_settings
from aegisnet.services.report_service import ReportService


class FakeIngestStore:
    """The IngestStore port, in memory, with a call log for chunking assertions."""

    def __init__(self) -> None:
        self.batches: dict[UUID, dict[str, object]] = {}
        self.events: dict[bytes, tuple[UUID, NormalizedEvent, datetime]] = {}
        self.rejects: list[tuple[UUID, RejectedLine]] = []
        self.event_calls: list[int] = []
        self.fail_on_store = False

    async def open_batch(self, provenance: BatchProvenance, started_at: datetime) -> UUID:
        batch_id = uuid4()
        self.batches[batch_id] = {
            "provenance": provenance,
            "status": IngestStatus.received,
            "counts": BatchCounts(),
            "started_at": started_at,
            "finished_at": None,
        }
        return batch_id

    async def mark_normalizing(self, batch_id: UUID) -> None:
        self.batches[batch_id]["status"] = IngestStatus.normalizing

    async def store_events(
        self, batch_id: UUID, events: Sequence[NormalizedEvent], ingested_at: datetime
    ) -> int:
        if self.fail_on_store:
            raise RuntimeError("storage unavailable")
        self.event_calls.append(len(events))
        new = 0
        for event in events:
            if event.event_hash not in self.events:
                self.events[event.event_hash] = (batch_id, event, ingested_at)
                new += 1
        return new

    async def store_rejects(self, batch_id: UUID, rejects: Sequence[RejectedLine]) -> None:
        self.rejects.extend((batch_id, item) for item in rejects)

    async def finish_batch(
        self, batch_id: UUID, status: IngestStatus, counts: BatchCounts, finished_at: datetime
    ) -> None:
        self.batches[batch_id].update(status=status, counts=counts, finished_at=finished_at)

    async def list_batches(self, query: BatchFilter) -> Page[BatchSummary]:
        summaries = [await self.get_batch(batch_id) for batch_id in self.batches]
        rows = [s for s in summaries if s is not None]
        if query.status is not None:
            rows = [s for s in rows if s.status is query.status]
        if query.source_label is not None:
            rows = [s for s in rows if s.source_label == query.source_label]
        rows.sort(key=lambda s: (s.started_at, s.batch_id), reverse=True)
        return Page(items=tuple(rows[: query.limit]), next_cursor=None)

    async def list_rejects(
        self, batch_id: UUID, *, limit: int, cursor: str | None
    ) -> Page[RejectRow]:
        rows = [
            RejectRow(
                line_number=item.line_number,
                reason=item.reject.reason,
                detail=item.reject.detail,
                raw_excerpt=item.reject.raw_excerpt,
                created_at=STUB_TIME,
            )
            for owner, item in self.rejects
            if owner == batch_id
        ]
        return Page(items=tuple(rows[:limit]), next_cursor=None)

    async def get_batch(self, batch_id: UUID) -> BatchSummary | None:
        row = self.batches.get(batch_id)
        if row is None:
            return None
        provenance = row["provenance"]
        assert isinstance(provenance, BatchProvenance)
        counts = row["counts"]
        assert isinstance(counts, BatchCounts)
        status = row["status"]
        assert isinstance(status, IngestStatus)
        started = row["started_at"]
        assert isinstance(started, datetime)
        finished = row["finished_at"]
        assert finished is None or isinstance(finished, datetime)
        return BatchSummary(
            batch_id=batch_id,
            status=status,
            source_label=provenance.source_label,
            dataset_id=provenance.dataset_id,
            counts=counts,
            started_at=started,
            finished_at=finished,
        )


class FakeAssetStore:
    def __init__(self) -> None:
        self.rows: dict[UUID, AssetRecord] = {}
        self.create_many_calls = 0

    def _build(self, spec: AssetSpec, now: datetime, asset_id: UUID | None = None) -> AssetRecord:
        return AssetRecord(
            id=asset_id or uuid4(),
            hostname=spec.hostname,
            environment=spec.environment,
            owner=spec.owner,
            criticality=spec.criticality,
            tags=tuple(spec.tags),
            description=spec.description,
            is_active=True,
            created_at=now,
            updated_at=now,
            networks=tuple(NetworkView(uuid4(), n.cidr, n.is_primary) for n in spec.networks),
        )

    async def create(self, spec: AssetSpec, now: datetime) -> AssetRecord:
        record = self._build(spec, now)
        self.rows[record.id] = record
        return record

    async def create_many(
        self, specs: Sequence[AssetSpec], now: datetime
    ) -> tuple[AssetRecord, ...]:
        self.create_many_calls += 1
        created = tuple(self._build(spec, now) for spec in specs)
        for record in created:
            self.rows[record.id] = record
        return created

    async def get(self, asset_id: UUID) -> AssetRecord | None:
        return self.rows.get(asset_id)

    async def get_by_hostname(self, hostname: str) -> AssetRecord | None:
        return next((r for r in self.rows.values() if r.hostname == hostname), None)

    async def list(self, query: AssetFilter) -> Page[AssetRecord]:
        rows = [r for r in self.rows.values() if query.include_inactive or r.is_active]
        return Page(items=tuple(rows[: query.limit]), next_cursor=None)

    async def update(self, asset_id: UUID, patch: AssetPatch, now: datetime) -> AssetRecord | None:
        current = self.rows.get(asset_id)
        if current is None:
            return None
        values = {field: getattr(current, field) for field in current.__dataclass_fields__}
        for field in patch.model_fields_set:
            if field == "networks":
                assert patch.networks is not None
                values["networks"] = tuple(
                    NetworkView(uuid4(), n.cidr, n.is_primary) for n in patch.networks
                )
            elif field == "tags":
                values["tags"] = tuple(patch.tags or ())
            else:
                values[field] = getattr(patch, field)
        values["updated_at"] = now
        self.rows[asset_id] = AssetRecord(**values)
        return self.rows[asset_id]

    async def deactivate(self, asset_id: UUID, now: datetime) -> AssetRecord | None:
        return await self.update(asset_id, AssetPatch(is_active=False), now)

    async def networks(self, *, active_only: bool = True) -> tuple[NetworkRecord, ...]:
        return tuple(
            NetworkRecord(r.id, n.cidr, n.is_primary, r.created_at)
            for r in self.rows.values()
            if r.is_active or not active_only
            for n in r.networks
        )

    async def resolve(self, address: IPAddress) -> ResolvedAsset | None:
        hit = resolve_ip(address, await self.networks())
        return None if hit is None else ResolvedAsset(self.rows[hit.asset_id], hit.cidr)


def event_row_stub(
    event_id: UUID | None = None, payload: dict[str, object] | None = None
) -> EventRow:
    return EventRow(
        id=event_id or uuid4(),
        batch_id=uuid4(),
        event_time=STUB_TIME,
        ingested_at=STUB_TIME,
        event_type=EventType.dns,
        flow_id=1,
        src_ip=None,
        dest_ip=None,
        src_port=None,
        dest_port=None,
        proto=None,
        app_proto=None,
        bytes_toserver=None,
        bytes_toclient=None,
        pkts_toserver=None,
        pkts_toclient=None,
        dns_query="www.example.test",
        dns_rrtype="A",
        dns_rcode=None,
        http_host=None,
        http_url_path=None,
        sig_signature=None,
        sig_category=None,
        sig_signature_id=None,
        sig_severity=None,
        payload=payload,
    )


class FakeEventStore:
    def __init__(self) -> None:
        self.queries: list[EventQuery] = []
        self.rows: dict[UUID, EventRow] = {}
        # What ``batch_span`` answers for a batch with no rows here (the ingest fake keeps
        # its own rows); tests set it to exercise the post-ingest sweep.
        self.default_span: tuple[datetime, datetime] | None = None

    async def query(self, query: EventQuery) -> Page[EventRow]:
        self.queries.append(query)
        return Page(items=tuple(self.rows.values()), next_cursor=None)

    async def get(self, event_id: UUID, *, include_payload: bool) -> EventRow | None:
        row = self.rows.get(event_id)
        if row is None:
            return None
        # The SQL store returns the row it has, minus the payload column. Building a fresh
        # stub here would answer differently from the port this stands in for — every other
        # field would be a new uuid or a stub time, which is how a real caller of
        # `row.batch_id` gets a batch that does not exist (fakes.py, the same class of
        # defect as `FakeAlertStore.get` raising where the store returns empty tuples).
        return row if include_payload else replace(row, payload=None)

    async def load(
        self, start: datetime, end: datetime, *, max_events: int
    ) -> tuple[tuple[EventRow, ...], bool]:
        rows = sorted(
            (r for r in self.rows.values() if start <= r.event_time < end),
            key=lambda r: (r.event_time, r.id.int),
        )
        return tuple(rows[:max_events]), len(rows) > max_events

    async def batch_span(self, batch_id: UUID) -> tuple[datetime, datetime] | None:
        times = sorted(r.event_time for r in self.rows.values() if r.batch_id == batch_id)
        if times:
            return times[0], times[-1]
        return self.default_span

    async def hourly_outbound_bytes(
        self, networks: Sequence[IPNetwork], start: datetime, end: datetime
    ) -> tuple[tuple[datetime, int], ...]:
        totals: dict[datetime, int] = {}
        for r in self.rows.values():
            if r.event_type is not EventType.flow or r.src_ip is None or r.dest_ip is None:
                continue
            if not (start <= r.event_time < end) or not r.bytes_toserver:
                continue
            if is_internal(str(r.dest_ip)) or not any(r.src_ip in n for n in networks):
                continue
            hour = r.event_time.replace(minute=0, second=0, microsecond=0)
            totals[hour] = totals.get(hour, 0) + r.bytes_toserver
        return tuple(sorted(totals.items()))

    async def stats(self, query: EventQuery) -> EventStats:
        self.queries.append(query)
        return EventStats(total=len(self.rows), by_type=(("dns", len(self.rows)),), by_hour=())


# Cheap Argon2 parameters: the tests prove the flow, not the hardness.
REPO_ROOT = Path(__file__).resolve().parents[2]
"""The checkout, for the committed samples the offline brief lives in."""

TEST_HASHER = PasswordHasher(time_cost=1, memory_cost=8 * 1024, parallelism=1)
STUB_TIME = datetime(2026, 9, 1, tzinfo=UTC)


class Clock:
    """A settable clock shared by every fake and service in one app."""

    def __init__(self, start: datetime | None = None) -> None:
        self.now = start or datetime(2026, 9, 5, 12, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, delta: timedelta) -> None:
        self.now = self.now + delta

    def timestamp(self) -> float:
        return self.now.timestamp()


class FakeUserStore:
    def __init__(self) -> None:
        self.rows: dict[UUID, UserRecord] = {}

    async def create(
        self, email: str, display_name: str, password_hash: str, role: UserRole, now: datetime
    ) -> UserRecord:
        if any(r.email == email for r in self.rows.values()):
            raise EmailTakenError("email already registered")
        record = UserRecord(
            uuid4(), email, display_name, password_hash, role, True, 0, None, None, now
        )
        self.rows[record.id] = record
        return record

    async def get(self, user_id: UUID) -> UserRecord | None:
        return self.rows.get(user_id)

    async def get_by_email(self, email: str) -> UserRecord | None:
        return next((r for r in self.rows.values() if r.email == email), None)

    def _replace(self, user_id: UUID, **changes: object) -> None:
        current = self.rows[user_id]
        values = {f: getattr(current, f) for f in current.__dataclass_fields__}
        values.update(changes)
        self.rows[user_id] = UserRecord(**values)  # type: ignore[arg-type]

    async def record_failure(
        self, user_id: UUID, now: datetime, *, lock_until: datetime | None, reset: bool = False
    ) -> None:
        current = self.rows[user_id]
        changes: dict[str, object] = {
            "failed_login_count": 1 if reset else current.failed_login_count + 1
        }
        if lock_until is not None:
            changes["locked_until"] = lock_until
        elif reset:
            changes["locked_until"] = None
        self._replace(user_id, **changes)

    async def record_success(self, user_id: UUID, now: datetime) -> None:
        self._replace(user_id, failed_login_count=0, locked_until=None, last_login_at=now)

    async def list(self) -> tuple[UserRecord, ...]:
        return tuple(self.rows.values())

    def deactivate(self, user_id: UUID) -> None:
        self._replace(user_id, is_active=False)


class FakeRefreshTokenStore:
    def __init__(self) -> None:
        self.rows: dict[UUID, RefreshTokenRecord] = {}

    async def create(
        self,
        user_id: UUID,
        token_hash: bytes,
        issued_at: datetime,
        expires_at: datetime,
        user_agent_hash: bytes | None,
        ip_hash: bytes | None,
    ) -> RefreshTokenRecord:
        record = RefreshTokenRecord(uuid4(), user_id, token_hash, issued_at, expires_at, None, None)
        self.rows[record.id] = record
        return record

    async def get_by_hash(self, token_hash: bytes) -> RefreshTokenRecord | None:
        return next((r for r in self.rows.values() if r.token_hash == token_hash), None)

    def _replace(self, token_id: UUID, **changes: object) -> None:
        current = self.rows[token_id]
        values = {f: getattr(current, f) for f in current.__dataclass_fields__}
        values.update(changes)
        self.rows[token_id] = RefreshTokenRecord(**values)  # type: ignore[arg-type]

    async def rotate(self, old_id: UUID, new_id: UUID, now: datetime) -> None:
        self._replace(old_id, rotated_to=new_id, revoked_at=now)

    async def revoke_chain(self, token_id: UUID, now: datetime) -> int:
        revoked = 0
        current: UUID | None = token_id
        seen: set[UUID] = set()
        while current is not None and current not in seen and current in self.rows:
            seen.add(current)
            row = self.rows[current]
            if row.revoked_at is None:
                self._replace(current, revoked_at=now)
                revoked += 1
            current = row.rotated_to
        return revoked


class FakeServiceTokenStore:
    def __init__(self) -> None:
        self.rows: dict[UUID, ServiceTokenRecord] = {}

    async def create(
        self,
        name: str,
        token_hash: bytes,
        role: ServiceTokenRole,
        created_by: UUID | None,
        expires_at: datetime,
        now: datetime,
    ) -> ServiceTokenRecord:
        record = ServiceTokenRecord(
            uuid4(), name, token_hash, role, created_by, expires_at, None, None, now
        )
        self.rows[record.id] = record
        return record

    async def get_by_hash(self, token_hash: bytes) -> ServiceTokenRecord | None:
        return next((r for r in self.rows.values() if r.token_hash == token_hash), None)

    def _replace(self, token_id: UUID, **changes: object) -> None:
        current = self.rows[token_id]
        values = {f: getattr(current, f) for f in current.__dataclass_fields__}
        values.update(changes)
        self.rows[token_id] = ServiceTokenRecord(**values)  # type: ignore[arg-type]

    async def touch(self, token_id: UUID, now: datetime) -> None:
        self._replace(token_id, last_used_at=now)

    async def revoke(self, token_id: UUID, now: datetime) -> ServiceTokenRecord | None:
        if token_id not in self.rows:
            return None
        self._replace(token_id, revoked_at=now)
        return self.rows[token_id]

    async def list(self) -> tuple[ServiceTokenRecord, ...]:
        return tuple(self.rows.values())


class FakeAuditStore:
    def __init__(self) -> None:
        self.entries: list[AuditEntry] = []

    async def write(self, entry: AuditEntry) -> None:
        self.entries.append(entry)

    async def list(self, query: AuditFilter) -> Page[AuditRow]:
        rows = [AuditRow(index + 1, entry) for index, entry in enumerate(self.entries)]
        if query.action is not None:
            rows = [r for r in rows if r.entry.action == query.action]
        if query.result is not None:
            rows = [r for r in rows if r.entry.result is query.result]
        if query.actor_user_id is not None:
            rows = [r for r in rows if r.entry.actor_user_id == query.actor_user_id]
        rows.reverse()
        if query.cursor is not None:
            from aegisnet.domain.pagination import decode_int

            last = decode_int(query.cursor)
            rows = [r for r in rows if r.id < last]
        has_more = len(rows) > query.limit
        rows = rows[: query.limit]
        from aegisnet.domain.pagination import encode_int

        return Page(items=tuple(rows), next_cursor=encode_int(rows[-1].id) if has_more else None)

    def actions(self) -> list[str]:
        return [entry.action for entry in self.entries]


class FakeRateLimiter:
    """Fixed windows over the shared fake clock; can be told to fail like a dead Redis."""

    def __init__(self, clock: Clock) -> None:
        self.clock = clock
        self.counts: dict[tuple[str, str, int], int] = {}
        self.broken = False

    async def hit(
        self, name: str, subject: str, *, limit: int, window_seconds: int, cost: int = 1
    ) -> RateLimitDecision:
        if self.broken:
            from redis.exceptions import ConnectionError as RedisConnectionError

            raise RedisConnectionError("redis is down")
        now = self.clock.timestamp()
        index = int(now // window_seconds)
        key = (name, subject, index)
        self.counts[key] = self.counts.get(key, 0) + cost
        count = self.counts[key]
        retry_after = max(1, math.ceil((index + 1) * window_seconds - now))
        return RateLimitDecision(
            allowed=count <= limit,
            remaining=max(limit - count, 0),
            retry_after=retry_after if count > limit else 0,
        )


class FakeDenylist:
    def __init__(self) -> None:
        self.denied: set[str] = set()

    async def add(self, token_id: str, ttl_seconds: int) -> None:
        self.denied.add(token_id)

    async def contains(self, token_id: str) -> bool:
        return token_id in self.denied


class FakeRuleStore:
    def __init__(self) -> None:
        self.rows: dict[str, RuleRecord] = {}

    async def upsert(
        self,
        *,
        rule_id: str,
        name: str,
        version: int,
        base_severity: int,
        window_seconds: int,
        params: dict[str, object],
        description: str,
        mitre_hint: str | None,
        now: datetime,
    ) -> RuleRecord:
        current = self.rows.get(rule_id)
        record = RuleRecord(
            id=current.id if current else uuid4(),
            rule_id=rule_id,
            name=name,
            version=version,
            enabled=current.enabled if current else True,
            base_severity=base_severity,
            window_seconds=window_seconds,
            params=dict(params),
            description=description,
            mitre_hint=mitre_hint,
            updated_at=now,
        )
        self.rows[rule_id] = record
        return record

    async def list(self) -> tuple[RuleRecord, ...]:
        return tuple(self.rows[k] for k in sorted(self.rows))

    def set_enabled(self, rule_id: str, enabled: bool) -> None:
        current = self.rows[rule_id]
        values = {f: getattr(current, f) for f in current.__dataclass_fields__}
        values["enabled"] = enabled
        self.rows[rule_id] = RuleRecord(**values)  # type: ignore[arg-type]


class FakeDetectorRunStore:
    def __init__(self) -> None:
        self.rows: list[DetectorRunRecord] = []

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
    ) -> DetectorRunRecord:
        record = DetectorRunRecord(
            uuid4(),
            rule_id,
            window_start,
            window_end,
            events_examined,
            alerts_created,
            status,
            error_detail,
            duration_ms,
            now,
        )
        self.rows.append(record)
        return record

    async def list(self, *, limit: int) -> tuple[DetectorRunRecord, ...]:
        return tuple(reversed(self.rows))[:limit]


class FakeIncidentStore:
    """The incident store in memory, with the two constraints that matter kept honest: an
    alert belongs to one case, and a case says the same thing about an alert once."""

    def __init__(self, alert_store: FakeAlertStore | None = None) -> None:
        self.rows: dict[UUID, IncidentRecord] = {}
        self.alerts: dict[UUID, UUID] = {}
        """alert id -> incident id, which is the UNIQUE that makes a re-run a no-op."""
        self.timeline: dict[UUID, list[TimelineEntryRecord]] = {}
        self.notes: dict[UUID, list[NoteRecord]] = {}
        self.ordinal = 0
        self._alert_store = alert_store
        """Where the linked alerts come from on a detail; ``None`` means the detail carries
        their ids only, which is all the correlation tests ever look at."""

    async def open_case(
        self,
        incident: NewIncident,
        entries: Sequence[NewTimelineEntry],
        *,
        now: datetime,
        source: IncidentAlertSource = IncidentAlertSource.correlation_engine,
    ) -> IncidentRecord:
        self.ordinal += 1
        record = IncidentRecord(
            id=uuid4(),
            case_number=case_number(now.year, self.ordinal),
            title=incident.title,
            severity=incident.severity,
            severity_rationale=dict(incident.severity_rationale),
            status=IncidentStatus.new,
            primary_asset_id=incident.primary_asset_id,
            correlation_key=incident.correlation_key,
            window_start=incident.window_start,
            window_end=incident.window_end,
            distinct_rule_count=incident.distinct_rule_count,
            assigned_to=None,
            closed_at=None,
            closure_reason=None,
            created_at=now,
            updated_at=now,
        )
        self.rows[record.id] = record
        self.timeline[record.id] = []
        self._link(record.id, incident.alert_ids)
        self._append(record.id, entries, now)
        return record

    async def newest_open_for_key(self, correlation_key: str) -> IncidentRecord | None:
        candidates = [
            row
            for row in self.rows.values()
            if row.correlation_key == correlation_key and not is_closed(row.status)
        ]
        return max(candidates, key=lambda r: (r.window_end, r.created_at), default=None)

    async def newest_closed_for_key(self, correlation_key: str) -> IncidentRecord | None:
        candidates = [
            row
            for row in self.rows.values()
            if row.correlation_key == correlation_key and is_closed(row.status)
        ]
        return max(candidates, key=lambda r: (r.window_end, r.created_at), default=None)

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
        # Mirrors the SQL store's row-locked re-read: a case an analyst closed between
        # correlation's read and its write absorbs nothing (ADR-023).
        current = self.rows.get(incident_id)
        if current is None or is_closed(current.status):
            return 0
        linked = self._link(incident_id, alert_ids)
        self._append(incident_id, entries, now)
        if linked:
            current = self.rows[incident_id]
            self.rows[incident_id] = replace(
                current,
                severity=severity,
                severity_rationale=dict(severity_rationale),
                title=title,
                window_end=max(current.window_end, window_end),
                distinct_rule_count=distinct_rule_count,
                updated_at=now,
            )
        return linked

    async def already_linked(self, alert_ids: Sequence[UUID]) -> set[UUID]:
        return {alert_id for alert_id in alert_ids if alert_id in self.alerts}

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
        current = self.rows.get(incident_id)
        # The compare half of the compare-and-set: a caller working from a stale read loses.
        if current is None or current.status is not expected:
            return None
        closing = is_closed(target)
        updated = replace(
            current,
            status=target,
            closed_at=now if closing else None,
            closure_reason=closure_reason if closing else None,
            updated_at=now,
        )
        self.rows[incident_id] = updated
        self._append_one(incident_id, entry, now)
        return updated

    async def add_note(
        self,
        incident_id: UUID,
        *,
        body: str,
        author_id: UUID | None,
        entry: NewTimelineEntry,
        now: datetime,
    ) -> NoteRecord | None:
        if incident_id not in self.rows:
            return None
        note = NoteRecord(
            id=uuid4(),
            incident_id=incident_id,
            author_id=author_id,
            body=body,
            created_at=now,
        )
        self.notes.setdefault(incident_id, []).append(note)
        self._append_one(
            incident_id, replace(entry, detail={**entry.detail, "note_id": str(note.id)}), now
        )
        self.rows[incident_id] = replace(self.rows[incident_id], updated_at=now)
        return note

    async def add_timeline_entry(
        self, incident_id: UUID, entry: NewTimelineEntry, *, now: datetime
    ) -> None:
        if incident_id in self.rows:
            self._append_one(incident_id, entry, now)

    async def list_notes(
        self, incident_id: UUID, *, limit: int, cursor: str | None
    ) -> Page[NoteRecord]:
        rows = sorted(
            self.notes.get(incident_id, []), key=lambda n: (n.created_at, n.id.int), reverse=True
        )
        if cursor is not None:
            moment, last_id = decode_time_id(cursor)
            rows = [n for n in rows if (n.created_at, n.id.int) < (moment, last_id.int)]
        has_more = len(rows) > limit
        rows = rows[:limit]
        return Page(
            items=tuple(rows),
            next_cursor=(
                encode_time_id(rows[-1].created_at, rows[-1].id) if has_more and rows else None
            ),
        )

    async def list_timeline(
        self, incident_id: UUID, *, limit: int, cursor: str | None
    ) -> Page[TimelineEntryRecord]:
        rows = self._ordered_timeline(incident_id)
        if cursor is not None:
            moment, last_id = decode_time_id(cursor)
            rows = [e for e in rows if (e.occurred_at, e.id.int) > (moment, last_id.int)]
        has_more = len(rows) > limit
        rows = rows[:limit]
        return Page(
            items=tuple(rows),
            next_cursor=(
                encode_time_id(rows[-1].occurred_at, rows[-1].id) if has_more and rows else None
            ),
        )

    async def list(self, query: IncidentFilter) -> Page[IncidentRecord]:
        rows = list(self.rows.values())
        if query.status is not None:
            rows = [r for r in rows if r.status is query.status]
        if query.open_only:
            rows = [r for r in rows if not is_closed(r.status)]
        if query.severity_min is not None:
            rows = [r for r in rows if r.severity >= query.severity_min]
        if query.correlation_key is not None:
            rows = [r for r in rows if r.correlation_key == query.correlation_key]
        rows.sort(key=lambda r: (r.created_at, r.id.int), reverse=True)
        if query.cursor is not None:
            moment, last_id = decode_time_id(query.cursor)
            rows = [r for r in rows if (r.created_at, r.id.int) < (moment, last_id.int)]
        has_more = len(rows) > query.limit
        rows = rows[: query.limit]
        cursor = encode_time_id(rows[-1].created_at, rows[-1].id) if has_more and rows else None
        return Page(items=tuple(rows), next_cursor=cursor)

    async def get(
        self, incident_id: UUID, *, timeline_limit: int = DETAIL_TIMELINE_LIMIT
    ) -> IncidentDetail | None:
        row = self.rows.get(incident_id)
        return None if row is None else self._detail(row, timeline_limit)

    async def get_by_case_number(
        self, case_number_value: str, *, timeline_limit: int = DETAIL_TIMELINE_LIMIT
    ) -> IncidentDetail | None:
        for row in self.rows.values():
            if row.case_number == case_number_value:
                return self._detail(row, timeline_limit)
        return None

    # ---- internals

    def _detail(self, row: IncidentRecord, timeline_limit: int) -> IncidentDetail:
        alerts = tuple(a for a, incident in self.alerts.items() if incident == row.id)
        records = (
            ()
            if self._alert_store is None
            else tuple(self._alert_store.rows[a] for a in alerts if a in self._alert_store.rows)
        )
        ordered = self._ordered_timeline(row.id)
        return IncidentDetail(
            incident=row,
            alert_ids=alerts,
            timeline=tuple(ordered[-timeline_limit:]),
            alerts=records,
            timeline_truncated=len(ordered) > timeline_limit,
        )

    def _ordered_timeline(self, incident_id: UUID) -> list[TimelineEntryRecord]:
        return sorted(self.timeline.get(incident_id, []), key=lambda e: (e.occurred_at, e.id.int))

    def _link(self, incident_id: UUID, alert_ids: Sequence[UUID]) -> int:
        linked = 0
        for alert_id in alert_ids:
            if alert_id in self.alerts:
                continue
            self.alerts[alert_id] = incident_id
            linked += 1
        return linked

    def _append(
        self, incident_id: UUID, entries: Sequence[NewTimelineEntry], now: datetime
    ) -> None:
        # The UNIQUE is (incident_id, entry_type, alert_id) and PostgreSQL counts NULLs as
        # distinct, so it only ever suppresses a repeat about the *same alert*. Entries
        # without one — a status change, a note — are never deduplicated by it.
        existing = {
            (e.entry_type, e.alert_id)
            for e in self.timeline.get(incident_id, [])
            if e.alert_id is not None
        }
        for entry in entries:
            if entry.alert_id is not None and (entry.entry_type, entry.alert_id) in existing:
                continue
            if entry.alert_id is not None:
                existing.add((entry.entry_type, entry.alert_id))
            self._append_one(incident_id, entry, now)

    def _append_one(self, incident_id: UUID, entry: NewTimelineEntry, now: datetime) -> None:
        self.timeline.setdefault(incident_id, []).append(
            TimelineEntryRecord(
                id=uuid4(),
                incident_id=incident_id,
                occurred_at=entry.occurred_at,
                entry_type=entry.entry_type,
                summary=entry.summary,
                detail=dict(entry.detail),
                alert_id=entry.alert_id,
                actor_user_id=entry.actor_user_id,
                created_at=now,
            )
        )


class FakeBriefStore:
    """Append-only in memory, with the same version allocation the SQL store does."""

    def __init__(self) -> None:
        self.rows: list[BriefRecord] = []

    async def create(self, brief: NewBrief, now: datetime) -> BriefRecord:
        version = 1 + max(
            (r.version for r in self.rows if r.incident_id == brief.incident_id), default=0
        )
        record = BriefRecord(
            id=uuid4(),
            incident_id=brief.incident_id,
            version=version,
            status=brief.status,
            source=brief.source,
            packet_hash=brief.packet_hash,
            packet_truncated=brief.packet_truncated,
            model=brief.model,
            summary=brief.summary,
            limitations=brief.limitations,
            claims=list(brief.claims),
            recommendations=list(brief.recommendations),
            has_unverified=brief.has_unverified,
            failure_reason=brief.failure_reason,
            prompt_tokens=brief.prompt_tokens,
            completion_tokens=brief.completion_tokens,
            requested_by=brief.requested_by,
            created_at=now,
            citations=tuple(brief.citations),
        )
        self.rows.append(record)
        return record

    async def list(self, incident_id: UUID) -> tuple[BriefRecord, ...]:
        found = [r for r in self.rows if r.incident_id == incident_id]
        return tuple(sorted(found, key=lambda r: r.version, reverse=True))

    async def get(self, incident_id: UUID, version: int) -> BriefRecord | None:
        return next(
            (r for r in self.rows if r.incident_id == incident_id and r.version == version), None
        )

    async def latest(self, incident_id: UUID) -> BriefRecord | None:
        found = await self.list(incident_id)
        return found[0] if found else None


class FakeAlertStore:
    def __init__(self) -> None:
        self.rows: dict[UUID, AlertRecord] = {}
        self.links: dict[
            UUID,
            tuple[tuple[tuple[UUID, SampleRole], ...], tuple[tuple[UUID, AlertAssetRole], ...]],
        ] = {}

    async def create_many(self, alerts: Sequence[NewAlert], now: datetime) -> int:
        existing = {row.dedup_key for row in self.rows.values()}
        created = 0
        for alert in alerts:
            if alert.dedup_key in existing:
                continue
            record = AlertRecord(
                id=uuid4(),
                rule_id=alert.rule_id,
                rule_version=alert.rule_version,
                dedup_key=alert.dedup_key,
                severity=alert.severity,
                confidence=alert.confidence,
                severity_rationale=dict(alert.severity_rationale),
                entity_type=alert.entity_type,
                entity_value=alert.entity_value,
                first_seen=alert.first_seen,
                last_seen=alert.last_seen,
                evidence=dict(alert.evidence),
                event_count=alert.event_count,
                status=AlertStatus.open,
                created_at=now,
            )
            self.rows[record.id] = record
            self.links[record.id] = (alert.samples, alert.assets)
            existing.add(alert.dedup_key)
            created += 1
        return created

    async def list(self, query: AlertFilter) -> Page[AlertRecord]:
        rows = list(self.rows.values())
        if query.severity_min is not None:
            rows = [r for r in rows if r.severity >= query.severity_min]
        if query.rule_id is not None:
            rows = [r for r in rows if r.rule_id == query.rule_id]
        if query.entity_type is not None:
            rows = [r for r in rows if r.entity_type is query.entity_type]
        if query.entity_value is not None:
            rows = [r for r in rows if r.entity_value == query.entity_value]
        if query.status is not None:
            rows = [r for r in rows if r.status is query.status]
        if query.time_from is not None:
            rows = [r for r in rows if r.first_seen >= query.time_from]
        if query.time_to is not None:
            rows = [r for r in rows if r.first_seen < query.time_to]
        rows.sort(key=lambda r: (r.first_seen, r.id.int), reverse=True)
        if query.cursor is not None:
            moment, last_id = decode_time_id(query.cursor)
            rows = [r for r in rows if (r.first_seen, r.id.int) < (moment, last_id.int)]
        has_more = len(rows) > query.limit
        rows = rows[: query.limit]
        cursor = encode_time_id(rows[-1].first_seen, rows[-1].id) if has_more and rows else None
        return Page(items=tuple(rows), next_cursor=cursor)

    async def get(self, alert_id: UUID) -> AlertDetail | None:
        record = self.rows.get(alert_id)
        if record is None:
            return None
        # An alert with no link rows is a real state, and the SQL store returns empty tuples
        # for it rather than raising — a test that puts a row in `rows` directly should get the
        # same answer here.
        events, assets = self.links.get(alert_id, ((), ()))
        return AlertDetail(alert=record, events=events, assets=assets)


class FakeBaselineStore:
    def __init__(self) -> None:
        self.rows: dict[tuple[UUID, BaselineMetric, int], BaselineRecord] = {}

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
    ) -> BaselineRecord:
        key = (asset_id, metric, window_days)
        current = self.rows.get(key)
        record = BaselineRecord(
            id=current.id if current else uuid4(),
            asset_id=asset_id,
            metric=metric,
            window_days=window_days,
            mean=mean,
            stddev=stddev,
            p95=p95,
            sample_count=sample_count,
            computed_at=now,
        )
        self.rows[key] = record
        return record

    async def list(self, *, metric: BaselineMetric | None = None) -> tuple[BaselineRecord, ...]:
        rows = [r for r in self.rows.values() if metric is None or r.metric is metric]
        return tuple(sorted(rows, key=lambda r: (r.asset_id.int, r.metric.value, r.window_days)))


class FakeWiring:
    """Everything the app needs, in memory, plus what tests need to inspect it."""

    def __init__(self, settings: Settings, spool_dir: Path) -> None:
        self.settings = settings
        self.clock = Clock()
        self.users = FakeUserStore()
        self.refresh_tokens = FakeRefreshTokenStore()
        self.service_tokens = FakeServiceTokenStore()
        self.audit_store = FakeAuditStore()
        self.ingest_store = FakeIngestStore()
        self.asset_store = FakeAssetStore()
        self.event_store = FakeEventStore()
        self.limiter = FakeRateLimiter(self.clock)
        self.denylist = FakeDenylist()
        self.spool = Spool(spool_dir)
        self.enqueued: list[tuple[str, UUID, str, str]] = []
        self.auth = AuthService(
            self.users,
            self.refresh_tokens,
            self.service_tokens,
            self.denylist,
            secret=settings.secret_key.get_secret_value(),
            policy=AuthPolicy.from_settings(settings),
            clock=self.clock,
            hasher=TEST_HASHER,
        )
        self.audit = AuditService(self.audit_store, clock=self.clock)
        self.ingest = IngestService(
            self.ingest_store, limits_from_settings(settings), clock=self.clock
        )
        self.assets = AssetService(self.asset_store, clock=self.clock)
        self.events = EventReadService(self.event_store)
        self.rule_store = FakeRuleStore()
        self.run_store = FakeDetectorRunStore()
        self.alert_store = FakeAlertStore()
        self.baseline_store = FakeBaselineStore()
        self.detection = DetectionService(
            self.rule_store,
            self.run_store,
            self.alert_store,
            self.event_store,
            self.assets,
            baselines=self.baseline_store,
            clock=self.clock,
        )
        self.baselines = BaselineService(
            self.asset_store, self.event_store, self.baseline_store, clock=self.clock
        )
        self.incident_store = FakeIncidentStore(self.alert_store)
        self.incidents = IncidentService(self.incident_store, clock=self.clock)
        self.brief_store = FakeBriefStore()
        self.reports = ReportService(
            self.incident_store,
            self.brief_store,
            alerts=self.alert_store,
            events=self.event_store,
            ingest=self.ingest_store,
            assets=self.assets,
        )
        self.briefs = BriefService(
            self.incident_store,
            self.brief_store,
            PerplexityClient(settings),
            samples_dir=REPO_ROOT / "samples",
            clock=self.clock,
        )
        self.sweeps: list[tuple[datetime, datetime]] = []
        self.baseline_requests: list[int] = []

    def services(self) -> AppServices:
        async def enqueue_upload(batch_id: UUID, spool_name: str, source_label: str) -> str:
            self.enqueued.append(("import_upload", batch_id, spool_name, source_label))
            return f"msg-{len(self.enqueued)}"

        async def enqueue_import(batch_id: UUID, dataset_id: str, source_label: str) -> str:
            self.enqueued.append(("import_dataset", batch_id, dataset_id, source_label))
            return f"msg-{len(self.enqueued)}"

        async def enqueue_sweep(start: datetime, end: datetime) -> str:
            self.sweeps.append((start, end))
            return f"sweep-{len(self.sweeps)}"

        async def enqueue_baselines(window_days: int) -> str:
            self.baseline_requests.append(window_days)
            return f"baselines-{len(self.baseline_requests)}"

        return AppServices(
            settings=self.settings,
            auth=self.auth,
            audit=self.audit,
            audit_read=AuditReadService(self.audit_store),
            ingest=self.ingest,
            assets=self.assets,
            events=self.events,
            limiter=self.limiter,
            spool=self.spool,
            enqueue_upload=enqueue_upload,
            enqueue_import=enqueue_import,
            detection=self.detection,
            enqueue_sweep=enqueue_sweep,
            baselines=self.baselines,
            enqueue_baselines=enqueue_baselines,
            incidents=self.incidents,
            briefs=self.briefs,
            reports=self.reports,
        )

    def factory(self) -> object:
        """The ``services_factory`` for ``create_app``; ignores the engine and cache."""

        def build(settings: Settings, engine: AsyncEngine, cache: Redis) -> AppServices:
            return self.services()

        return build

    # ---------------------------------------------------------------- helpers
    async def add_user(
        self,
        email: str,
        role: UserRole,
        password: str = "correct horse battery",  # noqa: S107
    ) -> UserRecord:
        return await self.auth.register_user(email, email.split("@")[0], password, role)

    async def login_headers(
        self,
        email: str,
        password: str = "correct horse battery",  # noqa: S107
    ) -> dict[str, str]:
        outcome = await self.auth.login(email, password, ip="127.0.0.1", user_agent="tests")
        return {"Authorization": f"Bearer {outcome.access_token}"}

    async def service_token_headers(self, name: str = "ingest-1") -> dict[str, str]:
        plaintext, _ = await self.auth.create_service_token(
            name, created_by=None, ttl=timedelta(days=1)
        )
        return {"X-Ingest-Token": plaintext}

    def audit_actions(self) -> Sequence[str]:
        return self.audit_store.actions()
