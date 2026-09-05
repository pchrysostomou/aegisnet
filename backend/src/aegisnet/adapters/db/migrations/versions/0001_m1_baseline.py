"""Milestone 1 baseline: nine foundation tables, their enum types, indexes and grants.

Revision ID: 0001_m1_baseline
Revises:
Create Date: 2026-09-04

Creates, in dependency order: users, service_tokens, refresh_tokens, audit_log,
ingest_batches, events, ingest_rejects, assets, asset_networks (docs/data-model.md).

Runs as the migrator role, which owns every object. The runtime role receives exactly:

- SELECT, INSERT, UPDATE on every table except audit_log;
- SELECT, INSERT on audit_log and USAGE on its identity sequence — never UPDATE or DELETE
  (THREAT_MODEL T-2.5, T-5.3; proven by tests/db/test_grants.py);
- SELECT on alembic_version, so a later readiness check can compare revisions.

No DELETE is granted anywhere: assets soft-delete, events are append-only, and the
retention job that will need DELETE is a later milestone with its own revision.
"""

from __future__ import annotations

import re
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import context, op
from sqlalchemy.dialects import postgresql as pg

revision: str = "0001_m1_baseline"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Enum labels, duplicated here on purpose: a revision must stay frozen even when the
# Python enums in aegisnet.domain.enums grow later.
ENUMS: dict[str, tuple[str, ...]] = {
    "source_type": ("suricata_eve",),
    "ingest_method": ("api_ndjson", "api_file", "registry_import"),
    "ingest_status": ("received", "normalizing", "complete", "failed"),
    "event_type": ("alert", "dns", "http", "flow", "tls", "fileinfo", "anomaly", "ssh", "other"),
    "reject_reason": (
        "json_parse",
        "schema_invalid",
        "missing_required",
        "timestamp_out_of_range",
        "too_large",
        "too_deep",
        "unsupported_event_type",
    ),
    "asset_environment": ("lab", "dev", "staging", "prod_sim"),
    "user_role": ("admin", "analyst", "viewer"),
    "service_token_role": ("ingest_service",),
    "audit_result": ("success", "denied", "error"),
}

TABLES_IN_ORDER: tuple[str, ...] = (
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
READ_WRITE_TABLES: tuple[str, ...] = tuple(t for t in TABLES_IN_ORDER if t != "audit_log")

HASH_BYTES = 32
_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,62}$")

UUID = pg.UUID(as_uuid=True)
TZ = sa.DateTime(timezone=True)
NOW = sa.text("now()")
NEW_UUID = sa.text("gen_random_uuid()")


def _enum(name: str) -> pg.ENUM:
    return pg.ENUM(*ENUMS[name], name=name, create_type=False)


def _app_role() -> str:
    """The runtime role, supplied by env.py from settings, allow-listed before it is quoted.

    The name is interpolated into GRANT statements, which take identifiers and not bind
    parameters, so it is validated against the PostgreSQL identifier grammar first and then
    quoted by the dialect. A name that fails validation aborts the migration.
    """
    role = context.config.attributes.get("app_role")
    if not isinstance(role, str) or not _IDENTIFIER.fullmatch(role):
        raise RuntimeError("app_role must be a plain PostgreSQL identifier; refusing to GRANT")
    return op.get_bind().dialect.identifier_preparer.quote(role)


def _grant(privileges: str, kind: str, name: str, role: str) -> None:
    # Identifiers only: `name` is a literal from this file and `role` has been validated and
    # quoted by _app_role(). Nothing user-supplied reaches this statement.
    op.execute(f"GRANT {privileges} ON {kind} {name} TO {role}")


def _hash_check(table: str, column: str) -> sa.CheckConstraint:
    return sa.CheckConstraint(
        f"octet_length({column}) = {HASH_BYTES}", name=f"ck_{table}_{column}_length"
    )


def upgrade() -> None:
    bind = op.get_bind()

    # citext is a trusted extension, so the migrator can create it with CREATE on the
    # database, which infra/postgres/init/01_roles.sh grants.
    op.execute("CREATE EXTENSION IF NOT EXISTS citext")

    for name, labels in ENUMS.items():
        pg.ENUM(*labels, name=name).create(bind, checkfirst=False)

    # ------------------------------------------------------------ security & access
    op.create_table(
        "users",
        sa.Column("id", UUID, server_default=NEW_UUID, nullable=False),
        sa.Column("email", pg.CITEXT(), nullable=False),
        sa.Column("display_name", sa.Text(), nullable=False),
        sa.Column("password_hash", sa.Text(), nullable=False),
        sa.Column("role", _enum("user_role"), nullable=False),
        sa.Column("is_active", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("failed_login_count", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("locked_until", TZ, nullable=True),
        sa.Column("last_login_at", TZ, nullable=True),
        sa.Column("created_at", TZ, server_default=NOW, nullable=False),
        sa.Column("updated_at", TZ, server_default=NOW, nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_users"),
        sa.UniqueConstraint("email", name="uq_users_email"),
        sa.CheckConstraint(
            "failed_login_count >= 0", name="ck_users_failed_login_count_non_negative"
        ),
    )

    op.create_table(
        "service_tokens",
        sa.Column("id", UUID, server_default=NEW_UUID, nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("token_hash", sa.LargeBinary(), nullable=False),
        sa.Column("role", _enum("service_token_role"), nullable=False),
        sa.Column("created_by", UUID, nullable=True),
        sa.Column("expires_at", TZ, nullable=False),
        sa.Column("revoked_at", TZ, nullable=True),
        sa.Column("last_used_at", TZ, nullable=True),
        sa.Column("created_at", TZ, server_default=NOW, nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_service_tokens"),
        sa.UniqueConstraint("name", name="uq_service_tokens_name"),
        sa.UniqueConstraint("token_hash", name="uq_service_tokens_token_hash"),
        sa.ForeignKeyConstraint(
            ["created_by"],
            ["users.id"],
            name="fk_service_tokens_created_by_users",
            ondelete="SET NULL",
        ),
        _hash_check("service_tokens", "token_hash"),
    )

    op.create_table(
        "refresh_tokens",
        sa.Column("id", UUID, server_default=NEW_UUID, nullable=False),
        sa.Column("user_id", UUID, nullable=False),
        sa.Column("token_hash", sa.LargeBinary(), nullable=False),
        sa.Column("issued_at", TZ, server_default=NOW, nullable=False),
        sa.Column("expires_at", TZ, nullable=False),
        sa.Column("rotated_to", UUID, nullable=True),
        sa.Column("revoked_at", TZ, nullable=True),
        sa.Column("user_agent_hash", sa.LargeBinary(), nullable=True),
        sa.Column("ip_hash", sa.LargeBinary(), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_refresh_tokens"),
        sa.UniqueConstraint("token_hash", name="uq_refresh_tokens_token_hash"),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], name="fk_refresh_tokens_user_id_users", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["rotated_to"],
            ["refresh_tokens.id"],
            name="fk_refresh_tokens_rotated_to_refresh_tokens",
            ondelete="SET NULL",
        ),
        _hash_check("refresh_tokens", "token_hash"),
    )
    op.create_index(
        "ix_refresh_tokens_user_id_issued_at",
        "refresh_tokens",
        ["user_id", sa.text("issued_at DESC")],
    )

    # No foreign keys on purpose: a referential action would rewrite audit rows (T-2.5).
    op.create_table(
        "audit_log",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("occurred_at", TZ, server_default=NOW, nullable=False),
        sa.Column("actor_user_id", UUID, nullable=True),
        sa.Column("actor_token_id", UUID, nullable=True),
        sa.Column("actor_ip", pg.INET(), nullable=True),
        sa.Column("action", sa.Text(), nullable=False),
        sa.Column("target_type", sa.Text(), nullable=False),
        sa.Column("target_id", sa.Text(), nullable=True),
        sa.Column("result", _enum("audit_result"), nullable=False),
        sa.Column("detail", pg.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("correlation_id", UUID, nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_audit_log"),
    )
    op.create_index("ix_audit_log_occurred_at", "audit_log", [sa.text("occurred_at DESC")])
    op.create_index(
        "ix_audit_log_actor_user_id_occurred_at",
        "audit_log",
        ["actor_user_id", sa.text("occurred_at DESC")],
    )
    op.create_index(
        "ix_audit_log_action_occurred_at", "audit_log", ["action", sa.text("occurred_at DESC")]
    )

    # ------------------------------------------------------------ ingest
    op.create_table(
        "ingest_batches",
        sa.Column("id", UUID, server_default=NEW_UUID, nullable=False),
        sa.Column("source_type", _enum("source_type"), nullable=False),
        sa.Column("source_label", sa.Text(), nullable=False),
        sa.Column("dataset_id", sa.Text(), nullable=True),
        sa.Column("dataset_licence", sa.Text(), nullable=True),
        sa.Column("dataset_citation", sa.Text(), nullable=True),
        sa.Column("ingest_method", _enum("ingest_method"), nullable=False),
        sa.Column("actor_user_id", UUID, nullable=True),
        sa.Column("actor_token_id", UUID, nullable=True),
        sa.Column("events_received", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("events_stored", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("events_duplicate", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("events_rejected", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column(
            "status",
            _enum("ingest_status"),
            server_default=sa.text("'received'"),
            nullable=False,
        ),
        sa.Column("started_at", TZ, server_default=NOW, nullable=False),
        sa.Column("finished_at", TZ, nullable=True),
        sa.Column("updated_at", TZ, server_default=NOW, nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_ingest_batches"),
        sa.ForeignKeyConstraint(
            ["actor_user_id"],
            ["users.id"],
            name="fk_ingest_batches_actor_user_id_users",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["actor_token_id"],
            ["service_tokens.id"],
            name="fk_ingest_batches_actor_token_id_service_tokens",
            ondelete="SET NULL",
        ),
        sa.CheckConstraint(
            "char_length(source_label) BETWEEN 1 AND 64",
            name="ck_ingest_batches_source_label_length",
        ),
        sa.CheckConstraint(
            "events_received >= 0 AND events_stored >= 0 "
            "AND events_duplicate >= 0 AND events_rejected >= 0",
            name="ck_ingest_batches_event_counts_non_negative",
        ),
    )
    op.create_index("ix_ingest_batches_started_at", "ingest_batches", [sa.text("started_at DESC")])
    op.create_index("ix_ingest_batches_status", "ingest_batches", ["status"])

    op.create_table(
        "events",
        sa.Column("id", UUID, server_default=NEW_UUID, nullable=False),
        sa.Column("batch_id", UUID, nullable=False),
        sa.Column("event_hash", sa.LargeBinary(), nullable=False),
        sa.Column("event_time", TZ, nullable=False),
        sa.Column("ingested_at", TZ, server_default=NOW, nullable=False),
        sa.Column("event_type", _enum("event_type"), nullable=False),
        sa.Column("flow_id", sa.BigInteger(), nullable=True),
        sa.Column("src_ip", pg.INET(), nullable=True),
        sa.Column("dest_ip", pg.INET(), nullable=True),
        sa.Column("src_port", sa.Integer(), nullable=True),
        sa.Column("dest_port", sa.Integer(), nullable=True),
        sa.Column("proto", sa.Text(), nullable=True),
        sa.Column("app_proto", sa.Text(), nullable=True),
        sa.Column("bytes_toserver", sa.BigInteger(), nullable=True),
        sa.Column("bytes_toclient", sa.BigInteger(), nullable=True),
        sa.Column("pkts_toserver", sa.BigInteger(), nullable=True),
        sa.Column("pkts_toclient", sa.BigInteger(), nullable=True),
        sa.Column("dns_query", sa.Text(), nullable=True),
        sa.Column("dns_rrtype", sa.Text(), nullable=True),
        sa.Column("dns_rcode", sa.Text(), nullable=True),
        sa.Column("http_host", sa.Text(), nullable=True),
        sa.Column("http_url_path", sa.Text(), nullable=True),
        sa.Column("sig_signature", sa.Text(), nullable=True),
        sa.Column("sig_category", sa.Text(), nullable=True),
        sa.Column("sig_signature_id", sa.Integer(), nullable=True),
        sa.Column("sig_severity", sa.Integer(), nullable=True),
        sa.Column("payload", pg.JSONB(), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_events"),
        sa.UniqueConstraint("event_hash", name="uq_events_event_hash"),
        sa.ForeignKeyConstraint(
            ["batch_id"],
            ["ingest_batches.id"],
            name="fk_events_batch_id_ingest_batches",
            ondelete="CASCADE",
        ),
        _hash_check("events", "event_hash"),
        sa.CheckConstraint(
            "src_port IS NULL OR src_port BETWEEN 0 AND 65535", name="ck_events_src_port_range"
        ),
        sa.CheckConstraint(
            "dest_port IS NULL OR dest_port BETWEEN 0 AND 65535", name="ck_events_dest_port_range"
        ),
    )
    op.create_index("ix_events_event_time", "events", [sa.text("event_time DESC")])
    op.create_index("ix_events_src_ip_event_time", "events", ["src_ip", sa.text("event_time DESC")])
    op.create_index(
        "ix_events_dest_ip_event_time", "events", ["dest_ip", sa.text("event_time DESC")]
    )
    op.create_index(
        "ix_events_event_type_event_time", "events", ["event_type", sa.text("event_time DESC")]
    )
    op.create_index(
        "ix_events_flow_id", "events", ["flow_id"], postgresql_where=sa.text("flow_id IS NOT NULL")
    )
    op.create_index(
        "ix_events_dest_port_event_time",
        "events",
        ["dest_port", sa.text("event_time DESC")],
        postgresql_where=sa.text("dest_port IS NOT NULL"),
    )
    op.create_index(
        "ix_events_payload",
        "events",
        ["payload"],
        postgresql_using="gin",
        postgresql_ops={"payload": "jsonb_path_ops"},
    )

    op.create_table(
        "ingest_rejects",
        sa.Column("id", UUID, server_default=NEW_UUID, nullable=False),
        sa.Column("batch_id", UUID, nullable=False),
        sa.Column("line_number", sa.Integer(), nullable=False),
        sa.Column("reason_code", _enum("reject_reason"), nullable=False),
        sa.Column("detail", sa.Text(), nullable=False),
        sa.Column("raw_excerpt", sa.Text(), nullable=True),
        sa.Column("created_at", TZ, server_default=NOW, nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_ingest_rejects"),
        sa.ForeignKeyConstraint(
            ["batch_id"],
            ["ingest_batches.id"],
            name="fk_ingest_rejects_batch_id_ingest_batches",
            ondelete="CASCADE",
        ),
        sa.CheckConstraint("line_number > 0", name="ck_ingest_rejects_line_number_positive"),
        sa.CheckConstraint("char_length(detail) <= 512", name="ck_ingest_rejects_detail_length"),
        sa.CheckConstraint(
            "raw_excerpt IS NULL OR char_length(raw_excerpt) <= 256",
            name="ck_ingest_rejects_raw_excerpt_length",
        ),
    )
    op.create_index(
        "ix_ingest_rejects_batch_id_line_number", "ingest_rejects", ["batch_id", "line_number"]
    )

    # ------------------------------------------------------------ assets
    op.create_table(
        "assets",
        sa.Column("id", UUID, server_default=NEW_UUID, nullable=False),
        sa.Column("hostname", sa.Text(), nullable=True),
        sa.Column("environment", _enum("asset_environment"), nullable=False),
        sa.Column("owner", sa.Text(), nullable=True),
        sa.Column("criticality", sa.SmallInteger(), server_default=sa.text("3"), nullable=False),
        sa.Column(
            "tags", pg.ARRAY(sa.Text()), server_default=sa.text("'{}'::text[]"), nullable=False
        ),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("is_active", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("created_at", TZ, server_default=NOW, nullable=False),
        sa.Column("updated_at", TZ, server_default=NOW, nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_assets"),
        sa.UniqueConstraint("hostname", name="uq_assets_hostname"),
        sa.CheckConstraint("criticality BETWEEN 1 AND 5", name="ck_assets_criticality_range"),
    )
    op.create_index("ix_assets_tags", "assets", ["tags"], postgresql_using="gin")

    op.create_table(
        "asset_networks",
        sa.Column("id", UUID, server_default=NEW_UUID, nullable=False),
        sa.Column("asset_id", UUID, nullable=False),
        sa.Column("cidr", pg.CIDR(), nullable=False),
        sa.Column("is_primary", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("created_at", TZ, server_default=NOW, nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_asset_networks"),
        sa.UniqueConstraint("asset_id", "cidr", name="uq_asset_networks_asset_id_cidr"),
        sa.ForeignKeyConstraint(
            ["asset_id"],
            ["assets.id"],
            name="fk_asset_networks_asset_id_assets",
            ondelete="CASCADE",
        ),
    )
    op.create_index(
        "ix_asset_networks_cidr",
        "asset_networks",
        ["cidr"],
        postgresql_using="gist",
        postgresql_ops={"cidr": "inet_ops"},
    )

    # ------------------------------------------------------------ grants (T-5.3)
    role = _app_role()
    for table in READ_WRITE_TABLES:
        _grant("SELECT, INSERT, UPDATE", "TABLE", table, role)
    _grant("SELECT, INSERT", "TABLE", "audit_log", role)
    _grant("USAGE, SELECT", "SEQUENCE", "audit_log_id_seq", role)
    _grant("SELECT", "TABLE", "alembic_version", role)


def downgrade() -> None:
    bind = op.get_bind()
    for table in reversed(TABLES_IN_ORDER):
        op.drop_table(table)
    for name in reversed(tuple(ENUMS)):
        pg.ENUM(name=name).drop(bind, checkfirst=False)
    op.execute("DROP EXTENSION IF EXISTS citext")
