"""ORM models for the Milestone 1 schema.

These mirror ``docs/data-model.md``. They are the *description* of the schema that the
application code will use; the schema itself is created only by the Alembic baseline
revision, never by ``metadata.create_all`` (repo convention: no auto-create in any
environment). ``tests/db/test_migrations.py`` proves that the two agree by running
Alembic's ``compare_metadata`` against a freshly migrated database.

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
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Enum,
    ForeignKey,
    Identity,
    Index,
    Integer,
    LargeBinary,
    MetaData,
    SmallInteger,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects import postgresql as pg
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

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
    """Normalised EVE records. Append-only in practice (ADR-001, ADR-005)."""

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

APP_ROLE_READ_WRITE_TABLES: tuple[str, ...] = tuple(t for t in M1_TABLES if t != "audit_log")
"""Tables on which the runtime role receives SELECT, INSERT and UPDATE. Soft-delete is the
rule for assets and events are append-only; the retention job that will need DELETE on
events arrives in a later milestone with its own revision."""

APP_ROLE_DELETE_TABLES: tuple[str, ...] = ("asset_networks",)
"""Tables on which the runtime role also holds DELETE: an asset's networks are attributes
that a PATCH replaces wholesale (revision 0002)."""
