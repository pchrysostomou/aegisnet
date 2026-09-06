"""ORM models for the whole schema: the M1 baseline through the M5 brief tables.

These mirror ``docs/data-model.md``. They are the *description* of the schema that the
application code uses; the schema itself is created only by the Alembic revisions, never
by ``metadata.create_all`` (repo convention: no auto-create in any environment).
``tests/db/test_migrations.py`` proves that the two agree by running Alembic's
``compare_metadata`` against a freshly migrated database.

Design notes:

- Primary keys are ``uuid`` with ``gen_random_uuid()`` (built into PostgreSQL 13+, so no
  extension is needed). ``audit_log`` uses a bigint identity, as the data model says.
- ``audit_log`` carries **no** foreign keys. A referential action such as ``ON DELETE SET
  NULL`` would rewrite audit rows when a user is deleted, which contradicts the append-only
  guarantee (THREAT_MODEL T-2.5). Actor ids are stored as plain uuids.
- Hashes are ``bytea`` with a length check, so a hex string cannot be stored by mistake.
- Enum columns use the PostgreSQL enum types created by the migration (``create_type=False``
  here), and the Python members live in :mod:`aegisnet.domain.enums`.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Identity,
    Index,
    Integer,
    LargeBinary,
    MetaData,
    Numeric,
    SmallInteger,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects import postgresql as pg
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from aegisnet.domain.enums import (
    AlertAssetRole,
    AlertStatus,
    AssetEnvironment,
    AuditResult,
    BaselineMetric,
    BriefSource,
    BriefStatus,
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

# Deterministic constraint names, so a migration can always refer to them and so that
# compare_metadata does not report spurious renames.
NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

HASH_BYTES = 32
"""Length of every stored sha256 digest (``event_hash``, ``token_hash``)."""


def _enum(enum_cls: type, name: str) -> Enum:
    """A PostgreSQL enum type owned by the migration, referenced here by name only."""
    return Enum(enum_cls, name=name, native_enum=True, create_type=False, validate_strings=True)


SOURCE_TYPE = _enum(SourceType, "source_type")
INGEST_METHOD = _enum(IngestMethod, "ingest_method")
INGEST_STATUS = _enum(IngestStatus, "ingest_status")
EVENT_TYPE = _enum(EventType, "event_type")
REJECT_REASON = _enum(RejectReason, "reject_reason")
ASSET_ENVIRONMENT = _enum(AssetEnvironment, "asset_environment")
USER_ROLE = _enum(UserRole, "user_role")
SERVICE_TOKEN_ROLE = _enum(ServiceTokenRole, "service_token_role")
AUDIT_RESULT = _enum(AuditResult, "audit_result")
ENTITY_TYPE = _enum(EntityType, "entity_type")
SAMPLE_ROLE = _enum(SampleRole, "alert_event_role")
ALERT_ASSET_ROLE = _enum(AlertAssetRole, "alert_asset_role")
DETECTOR_RUN_STATUS = _enum(DetectorRunStatus, "detector_run_status")
ALERT_STATUS = _enum(AlertStatus, "alert_status")
INCIDENT_STATUS = _enum(IncidentStatus, "incident_status")
TIMELINE_ENTRY_TYPE = _enum(TimelineEntryType, "timeline_entry_type")
INCIDENT_ALERT_SOURCE = _enum(IncidentAlertSource, "incident_alert_source")
BASELINE_METRIC = _enum(BaselineMetric, "baseline_metric")
BRIEF_STATUS = _enum(BriefStatus, "brief_status")
BRIEF_SOURCE = _enum(BriefSource, "brief_source")

ENUM_TYPES = (
    SOURCE_TYPE,
    INGEST_METHOD,
    INGEST_STATUS,
    EVENT_TYPE,
    REJECT_REASON,
    ASSET_ENVIRONMENT,
    USER_ROLE,
    SERVICE_TOKEN_ROLE,
    AUDIT_RESULT,
    ENTITY_TYPE,
    SAMPLE_ROLE,
    ALERT_ASSET_ROLE,
    DETECTOR_RUN_STATUS,
    ALERT_STATUS,
    BASELINE_METRIC,
    INCIDENT_STATUS,
    TIMELINE_ENTRY_TYPE,
    INCIDENT_ALERT_SOURCE,
    BRIEF_STATUS,
    BRIEF_SOURCE,
)


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)
    type_annotation_map = {  # noqa: RUF012 - read once by the declarative metaclass
        datetime: DateTime(timezone=True),
        uuid.UUID: pg.UUID(as_uuid=True),
        dict[str, Any]: pg.JSONB,
    }


def _uuid_pk() -> Mapped[uuid.UUID]:
    return mapped_column(primary_key=True, server_default=text("gen_random_uuid()"))


def _now() -> Mapped[datetime]:
    return mapped_column(nullable=False, server_default=text("now()"))


def _hash_column(*, unique: bool) -> Mapped[bytes]:
    return mapped_column(LargeBinary, nullable=False, unique=unique)


# ---------------------------------------------------------------- security & access


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = _uuid_pk()
    email: Mapped[str] = mapped_column(pg.CITEXT, nullable=False, unique=True)
    display_name: Mapped[str] = mapped_column(Text, nullable=False)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    role: Mapped[UserRole] = mapped_column(USER_ROLE, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))
    failed_login_count: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default=text("0")
    )
    locked_until: Mapped[datetime | None] = mapped_column(nullable=True)
    last_login_at: Mapped[datetime | None] = mapped_column(nullable=True)
    created_at: Mapped[datetime] = _now()
    updated_at: Mapped[datetime] = _now()

    __table_args__ = (
        CheckConstraint("failed_login_count >= 0", name="failed_login_count_non_negative"),
    )


class ServiceToken(Base):
    __tablename__ = "service_tokens"

    id: Mapped[uuid.UUID] = _uuid_pk()
    name: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    token_hash: Mapped[bytes] = _hash_column(unique=True)
    role: Mapped[ServiceTokenRole] = mapped_column(SERVICE_TOKEN_ROLE, nullable=False)
    # Nullable: a token minted from the operator CLI before any user exists has no creator.
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    expires_at: Mapped[datetime] = mapped_column(nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(nullable=True)
    created_at: Mapped[datetime] = _now()

    __table_args__ = (
        CheckConstraint(f"octet_length(token_hash) = {HASH_BYTES}", name="token_hash_length"),
    )


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id: Mapped[uuid.UUID] = _uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    token_hash: Mapped[bytes] = _hash_column(unique=True)
    issued_at: Mapped[datetime] = _now()
    expires_at: Mapped[datetime] = mapped_column(nullable=False)
    rotated_to: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("refresh_tokens.id", ondelete="SET NULL"), nullable=True
    )
    revoked_at: Mapped[datetime | None] = mapped_column(nullable=True)
    user_agent_hash: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    ip_hash: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)

    __table_args__ = (
        CheckConstraint(f"octet_length(token_hash) = {HASH_BYTES}", name="token_hash_length"),
        Index("ix_refresh_tokens_user_id_issued_at", "user_id", text("issued_at DESC")),
    )


class AuditLog(Base):
    """Append-only. The app role holds INSERT and SELECT only (T-2.5, T-5.3)."""

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    occurred_at: Mapped[datetime] = _now()
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(nullable=True)
    actor_token_id: Mapped[uuid.UUID | None] = mapped_column(nullable=True)
    actor_ip: Mapped[str | None] = mapped_column(pg.INET, nullable=True)
    action: Mapped[str] = mapped_column(Text, nullable=False)
    target_type: Mapped[str] = mapped_column(Text, nullable=False)
    target_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    result: Mapped[AuditResult] = mapped_column(AUDIT_RESULT, nullable=False)
    detail: Mapped[dict[str, Any]] = mapped_column(
        pg.JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    correlation_id: Mapped[uuid.UUID | None] = mapped_column(nullable=True)

    __table_args__ = (
        Index("ix_audit_log_occurred_at", text("occurred_at DESC")),
        Index("ix_audit_log_actor_user_id_occurred_at", "actor_user_id", text("occurred_at DESC")),
        Index("ix_audit_log_action_occurred_at", "action", text("occurred_at DESC")),
    )


# ---------------------------------------------------------------- ingest


class IngestBatch(Base):
    __tablename__ = "ingest_batches"

    id: Mapped[uuid.UUID] = _uuid_pk()
    source_type: Mapped[SourceType] = mapped_column(SOURCE_TYPE, nullable=False)
    source_label: Mapped[str] = mapped_column(Text, nullable=False)
    dataset_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    dataset_licence: Mapped[str | None] = mapped_column(Text, nullable=True)
    dataset_citation: Mapped[str | None] = mapped_column(Text, nullable=True)
    ingest_method: Mapped[IngestMethod] = mapped_column(INGEST_METHOD, nullable=False)
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    actor_token_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("service_tokens.id", ondelete="SET NULL"), nullable=True
    )
    events_received: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    events_stored: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    events_duplicate: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    events_rejected: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    status: Mapped[IngestStatus] = mapped_column(
        INGEST_STATUS, nullable=False, server_default=text("'received'")
    )
    started_at: Mapped[datetime] = _now()
    finished_at: Mapped[datetime | None] = mapped_column(nullable=True)
    updated_at: Mapped[datetime] = _now()

    __table_args__ = (
        CheckConstraint("char_length(source_label) BETWEEN 1 AND 64", name="source_label_length"),
        CheckConstraint(
            "events_received >= 0 AND events_stored >= 0 "
            "AND events_duplicate >= 0 AND events_rejected >= 0",
            name="event_counts_non_negative",
        ),
        Index("ix_ingest_batches_started_at", text("started_at DESC")),
        Index("ix_ingest_batches_status", "status"),
    )


class Event(Base):
    """Normalised EVE records. Append-only for the runtime role (ADR-001, ADR-005); the
    retention role prunes them on a period, keeping any event an alert still cites (ADR-033)."""

    __tablename__ = "events"

    id: Mapped[uuid.UUID] = _uuid_pk()
    batch_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("ingest_batches.id", ondelete="CASCADE"), nullable=False
    )
    event_hash: Mapped[bytes] = _hash_column(unique=True)
    event_time: Mapped[datetime] = mapped_column(nullable=False)
    ingested_at: Mapped[datetime] = _now()
    event_type: Mapped[EventType] = mapped_column(EVENT_TYPE, nullable=False)
    flow_id: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    src_ip: Mapped[str | None] = mapped_column(pg.INET, nullable=True)
    dest_ip: Mapped[str | None] = mapped_column(pg.INET, nullable=True)
    src_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dest_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    proto: Mapped[str | None] = mapped_column(Text, nullable=True)
    app_proto: Mapped[str | None] = mapped_column(Text, nullable=True)
    bytes_toserver: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    bytes_toclient: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    pkts_toserver: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    pkts_toclient: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    dns_query: Mapped[str | None] = mapped_column(Text, nullable=True)
    dns_rrtype: Mapped[str | None] = mapped_column(Text, nullable=True)
    dns_rcode: Mapped[str | None] = mapped_column(Text, nullable=True)
    http_host: Mapped[str | None] = mapped_column(Text, nullable=True)
    http_url_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    sig_signature: Mapped[str | None] = mapped_column(Text, nullable=True)
    sig_category: Mapped[str | None] = mapped_column(Text, nullable=True)
    sig_signature_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    sig_severity: Mapped[int | None] = mapped_column(Integer, nullable=True)
    payload: Mapped[dict[str, Any]] = mapped_column(pg.JSONB, nullable=False)

    __table_args__ = (
        CheckConstraint(f"octet_length(event_hash) = {HASH_BYTES}", name="event_hash_length"),
        CheckConstraint("src_port IS NULL OR src_port BETWEEN 0 AND 65535", name="src_port_range"),
        CheckConstraint(
            "dest_port IS NULL OR dest_port BETWEEN 0 AND 65535", name="dest_port_range"
        ),
        Index("ix_events_event_time", text("event_time DESC")),
        Index("ix_events_src_ip_event_time", "src_ip", text("event_time DESC")),
        Index("ix_events_dest_ip_event_time", "dest_ip", text("event_time DESC")),
        Index("ix_events_event_type_event_time", "event_type", text("event_time DESC")),
        Index("ix_events_flow_id", "flow_id", postgresql_where=text("flow_id IS NOT NULL")),
        Index(
            "ix_events_dest_port_event_time",
            "dest_port",
            text("event_time DESC"),
            postgresql_where=text("dest_port IS NOT NULL"),
        ),
        Index(
            "ix_events_payload",
            "payload",
            postgresql_using="gin",
            postgresql_ops={"payload": "jsonb_path_ops"},
        ),
    )


class IngestReject(Base):
    __tablename__ = "ingest_rejects"

    id: Mapped[uuid.UUID] = _uuid_pk()
    batch_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("ingest_batches.id", ondelete="CASCADE"), nullable=False
    )
    line_number: Mapped[int] = mapped_column(Integer, nullable=False)
    reason_code: Mapped[RejectReason] = mapped_column(REJECT_REASON, nullable=False)
    detail: Mapped[str] = mapped_column(Text, nullable=False)
    raw_excerpt: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = _now()

    __table_args__ = (
        CheckConstraint("line_number > 0", name="line_number_positive"),
        CheckConstraint("char_length(detail) <= 512", name="detail_length"),
        CheckConstraint(
            "raw_excerpt IS NULL OR char_length(raw_excerpt) <= 256", name="raw_excerpt_length"
        ),
        Index("ix_ingest_rejects_batch_id_line_number", "batch_id", "line_number"),
    )


# ---------------------------------------------------------------- assets


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[uuid.UUID] = _uuid_pk()
    hostname: Mapped[str | None] = mapped_column(Text, nullable=True, unique=True)
    environment: Mapped[AssetEnvironment] = mapped_column(ASSET_ENVIRONMENT, nullable=False)
    owner: Mapped[str | None] = mapped_column(Text, nullable=True)
    criticality: Mapped[int] = mapped_column(SmallInteger, nullable=False, server_default=text("3"))
    tags: Mapped[list[str]] = mapped_column(
        pg.ARRAY(Text), nullable=False, server_default=text("'{}'::text[]")
    )
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))
    created_at: Mapped[datetime] = _now()
    updated_at: Mapped[datetime] = _now()

    __table_args__ = (
        CheckConstraint("criticality BETWEEN 1 AND 5", name="criticality_range"),
        Index("ix_assets_tags", "tags", postgresql_using="gin"),
    )


class AssetNetwork(Base):
    __tablename__ = "asset_networks"

    id: Mapped[uuid.UUID] = _uuid_pk()
    asset_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
    )
    cidr: Mapped[str] = mapped_column(pg.CIDR, nullable=False)
    is_primary: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    created_at: Mapped[datetime] = _now()

    __table_args__ = (
        UniqueConstraint("asset_id", "cidr", name="uq_asset_networks_asset_id_cidr"),
        Index(
            "ix_asset_networks_cidr",
            "cidr",
            postgresql_using="gist",
            postgresql_ops={"cidr": "inet_ops"},
        ),
    )


# ---------------------------------------------------------------- detection (M2, revision 0003)


class DetectionRule(Base):
    """Registry so alerts are reproducible against the exact rule version that fired."""

    __tablename__ = "detection_rules"

    id: Mapped[uuid.UUID] = _uuid_pk()
    rule_id: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))
    base_severity: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    window_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    params: Mapped[dict[str, Any]] = mapped_column(pg.JSONB, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    mitre_hint: Mapped[str | None] = mapped_column(Text, nullable=True)
    updated_at: Mapped[datetime] = _now()

    __table_args__ = (
        CheckConstraint("base_severity BETWEEN 1 AND 5", name="base_severity_range"),
        CheckConstraint("window_seconds > 0", name="window_seconds_positive"),
        CheckConstraint("version >= 1", name="version_positive"),
    )


class DetectorRun(Base):
    """One row per rule per sweep: observability and failure isolation (ARCHITECTURE §7)."""

    __tablename__ = "detector_runs"

    id: Mapped[uuid.UUID] = _uuid_pk()
    rule_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("detection_rules.id", ondelete="CASCADE"), nullable=False
    )
    window_start: Mapped[datetime] = mapped_column(nullable=False)
    window_end: Mapped[datetime] = mapped_column(nullable=False)
    events_examined: Mapped[int] = mapped_column(Integer, nullable=False)
    alerts_created: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[DetectorRunStatus] = mapped_column(DETECTOR_RUN_STATUS, nullable=False)
    error_detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = _now()

    __table_args__ = (
        CheckConstraint("window_end > window_start", name="window_order"),
        Index("ix_detector_runs_created_at", text("created_at DESC")),
    )


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[uuid.UUID] = _uuid_pk()
    rule_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("detection_rules.id", ondelete="RESTRICT"), nullable=False
    )
    rule_version: Mapped[int] = mapped_column(Integer, nullable=False)
    dedup_key: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    severity: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    confidence: Mapped[Decimal] = mapped_column(Numeric(3, 2), nullable=False)
    severity_rationale: Mapped[dict[str, Any]] = mapped_column(pg.JSONB, nullable=False)
    entity_type: Mapped[EntityType] = mapped_column(ENTITY_TYPE, nullable=False)
    entity_value: Mapped[str] = mapped_column(Text, nullable=False)
    first_seen: Mapped[datetime] = mapped_column(nullable=False)
    last_seen: Mapped[datetime] = mapped_column(nullable=False)
    evidence: Mapped[dict[str, Any]] = mapped_column(pg.JSONB, nullable=False)
    event_count: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[AlertStatus] = mapped_column(
        ALERT_STATUS, nullable=False, server_default=text("'open'")
    )
    created_at: Mapped[datetime] = _now()

    __table_args__ = (
        CheckConstraint("severity BETWEEN 1 AND 5", name="severity_range"),
        CheckConstraint("confidence BETWEEN 0 AND 1", name="confidence_range"),
        CheckConstraint("event_count >= 1", name="event_count_positive"),
        CheckConstraint("last_seen >= first_seen", name="seen_order"),
        Index("ix_alerts_severity_first_seen", text("severity DESC"), text("first_seen DESC")),
        Index("ix_alerts_entity", "entity_type", "entity_value", "first_seen"),
        Index("ix_alerts_first_seen_id", text("first_seen DESC"), text("id DESC")),
        Index("ix_alerts_evidence", "evidence", postgresql_using="gin"),
    )


class AlertEvent(Base):
    """Sampled, capped links from an alert to the events behind it."""

    __tablename__ = "alert_events"

    alert_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True
    )
    event_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("events.id", ondelete="CASCADE"), primary_key=True
    )
    role: Mapped[SampleRole] = mapped_column(SAMPLE_ROLE, nullable=False)


class AlertAsset(Base):
    __tablename__ = "alert_assets"

    alert_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), primary_key=True
    )
    role: Mapped[AlertAssetRole] = mapped_column(ALERT_ASSET_ROLE, nullable=False)


class AssetBaseline(Base):
    """Rolling statistics for D-005 and later rules, recomputed on a schedule and never
    inside detector logic."""

    __tablename__ = "asset_baselines"

    id: Mapped[uuid.UUID] = _uuid_pk()
    asset_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
    )
    metric: Mapped[BaselineMetric] = mapped_column(BASELINE_METRIC, nullable=False)
    window_days: Mapped[int] = mapped_column(Integer, nullable=False)
    mean: Mapped[float] = mapped_column(Float, nullable=False)
    stddev: Mapped[float] = mapped_column(Float, nullable=False)
    p95: Mapped[float] = mapped_column(Float, nullable=False)
    sample_count: Mapped[int] = mapped_column(Integer, nullable=False)
    computed_at: Mapped[datetime] = _now()

    __table_args__ = (
        UniqueConstraint("asset_id", "metric", "window_days", name="uq_asset_baselines_asset_id"),
        CheckConstraint("window_days > 0", name="window_days_positive"),
    )


M1_TABLES: tuple[str, ...] = (
    "users",
    "service_tokens",
    "refresh_tokens",
    "audit_log",
    "ingest_batches",
    "events",
    "ingest_rejects",
    "assets",
    "asset_networks",
)
"""The nine tables the Milestone 1 baseline creates, in dependency order."""


class Incident(Base):
    """A case: the alerts about one entity that tell one story (ADR-023)."""

    __tablename__ = "incidents"

    id: Mapped[uuid.UUID] = _uuid_pk()
    case_number: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    severity_rationale: Mapped[dict[str, Any]] = mapped_column(pg.JSONB, nullable=False)
    status: Mapped[IncidentStatus] = mapped_column(
        INCIDENT_STATUS, nullable=False, server_default=IncidentStatus.new.value
    )
    primary_asset_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("assets.id", ondelete="SET NULL"), nullable=True
    )
    correlation_key: Mapped[str] = mapped_column(Text, nullable=False)
    window_start: Mapped[datetime] = mapped_column(nullable=False)
    window_end: Mapped[datetime] = mapped_column(nullable=False)
    distinct_rule_count: Mapped[int] = mapped_column(Integer, nullable=False)
    assigned_to: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    closed_at: Mapped[datetime | None] = mapped_column(nullable=True)
    closure_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = _now()
    updated_at: Mapped[datetime] = _now()

    __table_args__ = (
        CheckConstraint("severity BETWEEN 1 AND 5", name="ck_incidents_severity_range"),
        CheckConstraint("window_end >= window_start", name="ck_incidents_window_order"),
        CheckConstraint(
            "distinct_rule_count >= 1", name="ck_incidents_distinct_rule_count_positive"
        ),
        CheckConstraint(
            "(status IN ('closed_true_positive', 'closed_false_positive', 'closed_benign'))"
            " = (closed_at IS NOT NULL)",
            name="ck_incidents_closed_at_matches_status",
        ),
        Index("ix_incidents_created_at", text("created_at DESC")),
        Index("ix_incidents_status", "status"),
        # The lookup correlation makes on every run: the open case for this entity, most
        # recent first. Partial, because a closed case never absorbs a new alert (ADR-023).
        Index(
            "ix_incidents_open_by_key",
            "correlation_key",
            text("window_end DESC"),
            postgresql_where=text(
                "status NOT IN ('closed_true_positive', 'closed_false_positive', 'closed_benign')"
            ),
        ),
    )


class IncidentAlert(Base):
    """Which alerts are in which case. One alert belongs to one case, which is what keeps a
    re-run from fanning a case out into several."""

    __tablename__ = "incident_alerts"

    incident_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True
    )
    alert_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True, unique=True
    )
    added_at: Mapped[datetime] = _now()
    added_by: Mapped[IncidentAlertSource] = mapped_column(INCIDENT_ALERT_SOURCE, nullable=False)


class IncidentTimelineEntry(Base):
    """The case's story, append-only."""

    __tablename__ = "incident_timeline"

    id: Mapped[uuid.UUID] = _uuid_pk()
    incident_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False
    )
    occurred_at: Mapped[datetime] = mapped_column(nullable=False)
    entry_type: Mapped[TimelineEntryType] = mapped_column(TIMELINE_ENTRY_TYPE, nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    detail: Mapped[dict[str, Any]] = mapped_column(
        pg.JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    alert_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("alerts.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = _now()

    __table_args__ = (
        UniqueConstraint(
            "incident_id", "entry_type", "alert_id", name="uq_incident_timeline_alert_entry"
        ),
        Index("ix_incident_timeline_incident_id", "incident_id", "occurred_at"),
    )


class IncidentNote(Base):
    """What an analyst wrote. No edits in v1: a note is a record of what was thought at the
    time, and rewriting it would make the timeline a worse witness."""

    __tablename__ = "incident_notes"

    id: Mapped[uuid.UUID] = _uuid_pk()
    incident_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False
    )
    author_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    body: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = _now()

    __table_args__ = (
        CheckConstraint("length(body) BETWEEN 1 AND 8000", name="ck_incident_notes_body_length"),
        Index("ix_incident_notes_incident_id", "incident_id", "created_at"),
    )


class InvestigationBriefRow(Base):
    """One attempt at a narrative about one case (ADR-030, ADR-031).

    Immutable: the runtime role may SELECT and INSERT and nothing else. Regenerating writes a
    new version rather than replacing this one, so an analyst can see that the first answer was
    refused and why. `packet_hash` records exactly what was sent to get it.
    """

    __tablename__ = "investigation_briefs"

    id: Mapped[uuid.UUID] = _uuid_pk()
    incident_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[BriefStatus] = mapped_column(BRIEF_STATUS, nullable=False)
    source: Mapped[BriefSource] = mapped_column(BRIEF_SOURCE, nullable=False)
    packet_hash: Mapped[str] = mapped_column(Text, nullable=False)
    packet_truncated: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("false")
    )
    model: Mapped[str | None] = mapped_column(Text, nullable=True)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    limitations: Mapped[str | None] = mapped_column(Text, nullable=True)
    claims: Mapped[list[Any]] = mapped_column(
        pg.JSONB, nullable=False, server_default=text("'[]'::jsonb")
    )
    recommendations: Mapped[list[Any]] = mapped_column(
        pg.JSONB, nullable=False, server_default=text("'[]'::jsonb")
    )
    has_unverified: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("false")
    )
    failure_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    prompt_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    completion_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    requested_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = _now()

    __table_args__ = (
        UniqueConstraint("incident_id", "version", name="uq_investigation_briefs_version"),
        CheckConstraint("version >= 1", name="ck_investigation_briefs_version_positive"),
        CheckConstraint(
            "(status = 'complete') = (summary IS NOT NULL)",
            name="ck_investigation_briefs_summary_matches_status",
        ),
        CheckConstraint(
            "(status = 'failed') = (failure_reason IS NOT NULL)",
            name="ck_investigation_briefs_reason_matches_status",
        ),
        Index("ix_investigation_briefs_incident", "incident_id", text("version DESC")),
    )


class BriefCitation(Base):
    """A source a brief pointed at. https only, said here as well as in the domain, because a
    citation is a link somebody will click."""

    __tablename__ = "brief_citations"

    id: Mapped[uuid.UUID] = _uuid_pk()
    brief_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("investigation_briefs.id", ondelete="CASCADE"), nullable=False
    )
    citation_id: Mapped[int] = mapped_column(Integer, nullable=False)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = _now()

    __table_args__ = (
        UniqueConstraint("brief_id", "citation_id", name="uq_brief_citations_citation_id"),
        CheckConstraint("url LIKE 'https://%'", name="ck_brief_citations_https"),
        Index("ix_brief_citations_brief_id", "brief_id"),
    )


M2_TABLES: tuple[str, ...] = (
    "detection_rules",
    "detector_runs",
    "alerts",
    "alert_events",
    "alert_assets",
    "asset_baselines",
)
"""The six detection tables revision 0003 adds (Milestone 2, Chunk 9), in dependency order."""

M3_TABLES: tuple[str, ...] = (
    "incidents",
    "incident_alerts",
    "incident_timeline",
    "incident_notes",
)

M5_TABLES: tuple[str, ...] = (
    "investigation_briefs",
    "brief_citations",
)
"""The two brief tables revision 0005 adds (Milestone 5, Chunk 23)."""

ALL_TABLES: tuple[str, ...] = M1_TABLES + M2_TABLES + M3_TABLES + M5_TABLES


APP_ROLE_APPEND_ONLY_TABLES: tuple[str, ...] = ("audit_log", *M5_TABLES)
"""Tables the runtime role may SELECT and INSERT and nothing else. The audit log because it is
evidence of what people did; the brief tables because a brief is evidence of what a model said
and of exactly what was sent to get it. Regenerating writes a new version."""

APP_ROLE_READ_WRITE_TABLES: tuple[str, ...] = tuple(
    t for t in ALL_TABLES if t not in APP_ROLE_APPEND_ONLY_TABLES
)
"""Tables on which the runtime role receives SELECT, INSERT and UPDATE. Soft-delete is the
rule for assets, and events are append-only *for this role*; DELETE on events belongs to
`aegisnet_retention` (revision 0006, ADR-033), which is the whole reason that role exists."""

APP_ROLE_DELETE_TABLES: tuple[str, ...] = ("asset_networks",)
"""Tables on which the runtime role also holds DELETE: an asset's networks are attributes
that a PATCH replaces wholesale (revision 0002)."""
