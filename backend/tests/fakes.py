"""In-memory implementations of the ports, and a services factory that wires them into
the real FastAPI app. The routes under test are the production routes; only the edges
(database, Redis, queue, spool directory) are replaced."""

from __future__ import annotations

import math
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

from argon2 import PasswordHasher
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncEngine

from aegisnet.adapters.db.auth_store import EmailTakenError
from aegisnet.adapters.files.spool import Spool
from aegisnet.api.deps import AppServices
from aegisnet.config import Settings
from aegisnet.domain.assets import (
    AssetPatch,
    AssetSpec,
    IPAddress,
    NetworkRecord,
    resolve_ip,
)
from aegisnet.domain.enums import (
    AlertAssetRole,
    AlertStatus,
    DetectorRunStatus,
    EventType,
    IngestStatus,
    SampleRole,
    ServiceTokenRole,
    UserRole,
)
from aegisnet.domain.models import NormalizedEvent
from aegisnet.domain.pagination import decode_time_id, encode_time_id
from aegisnet.domain.ports import (
    AlertDetail,
    AlertFilter,
    AlertRecord,
    AssetFilter,
    AssetRecord,
    AuditEntry,
    AuditFilter,
    AuditRow,
    BatchCounts,
    BatchFilter,
    BatchProvenance,
    BatchSummary,
    DetectorRunRecord,
    EventQuery,
    EventRow,
    EventStats,
    NetworkView,
    NewAlert,
    Page,
    RateLimitDecision,
    RefreshTokenRecord,
    RejectedLine,
    RejectRow,
    ResolvedAsset,
    RuleRecord,
    ServiceTokenRecord,
    UserRecord,
)
from aegisnet.services.asset_service import AssetService
from aegisnet.services.audit_service import AuditReadService, AuditService
from aegisnet.services.auth_service import AuthPolicy, AuthService
from aegisnet.services.detection_service import DetectionService
from aegisnet.services.event_read_service import EventReadService
from aegisnet.services.ingest_service import IngestService, limits_from_settings


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

    async def query(self, query: EventQuery) -> Page[EventRow]:
        self.queries.append(query)
        return Page(items=tuple(self.rows.values()), next_cursor=None)

    async def get(self, event_id: UUID, *, include_payload: bool) -> EventRow | None:
        row = self.rows.get(event_id)
        if row is None:
            return None
        return row if include_payload else event_row_stub(row.id, None)

    async def load(
        self, start: datetime, end: datetime, *, max_events: int
    ) -> tuple[tuple[EventRow, ...], bool]:
        rows = sorted(
            (r for r in self.rows.values() if start <= r.event_time < end),
            key=lambda r: (r.event_time, r.id.int),
        )
        return tuple(rows[:max_events]), len(rows) > max_events

    async def stats(self, query: EventQuery) -> EventStats:
        self.queries.append(query)
        return EventStats(total=len(self.rows), by_type=(("dns", len(self.rows)),), by_hour=())


# Cheap Argon2 parameters: the tests prove the flow, not the hardness.
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
        self, user_id: UUID, now: datetime, *, lock_until: datetime | None
    ) -> None:
        current = self.rows[user_id]
        changes: dict[str, object] = {"failed_login_count": current.failed_login_count + 1}
        if lock_until is not None:
            changes["locked_until"] = lock_until
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
        events, assets = self.links[alert_id]
        return AlertDetail(alert=record, events=events, assets=assets)


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
        self.detection = DetectionService(
            self.rule_store,
            self.run_store,
            self.alert_store,
            self.event_store,
            self.assets,
            clock=self.clock,
        )
        self.sweeps: list[tuple[datetime, datetime]] = []

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
