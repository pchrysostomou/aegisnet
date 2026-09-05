"""The six detection tables (Milestone 2, Chunk 9; docs/data-model.md; ADR-018).

Revision ID: 0003_detection_tables
Revises: 0002_asset_network_delete_grant
Create Date: 2026-09-05

``detection_rules`` is the registry an alert is reproducible against, ``detector_runs``
records every rule of every sweep (success, error or skipped), ``alerts`` carries the
severity with the rationale that reproduces it and a ``dedup_key`` that is UNIQUE so a
re-sweep over the same window creates nothing, ``alert_events`` and ``alert_assets`` are
the sampled links, and ``asset_baselines`` holds the rolling statistics D-005 will read.
The runtime role gets SELECT, INSERT and UPDATE on all six, no DELETE (ADR-012).
"""

from __future__ import annotations

import re
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import context, op
from sqlalchemy.dialects import postgresql as pg

revision: str = "0003_detection_tables"
down_revision: str | None = "0002_asset_network_delete_grant"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

ENUMS: dict[str, tuple[str, ...]] = {
    "entity_type": ("asset", "src_ip", "dest_ip", "domain"),
    "alert_event_role": ("first", "last", "peak", "sample"),
    "alert_asset_role": ("source", "destination"),
    "detector_run_status": ("success", "error", "skipped"),
    "alert_status": ("open", "correlated", "suppressed"),
    "baseline_metric": (
        "outbound_bytes_per_hour",
        "distinct_dest_per_hour",
        "dns_queries_per_hour",
    ),
}
TABLES_IN_ORDER: tuple[str, ...] = (
    "detection_rules",
    "detector_runs",
    "alerts",
    "alert_events",
    "alert_assets",
    "asset_baselines",
)
_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,62}$")
UUID = pg.UUID(as_uuid=True)
TZ = sa.DateTime(timezone=True)
NOW = sa.text("now()")
NEW_UUID = sa.text("gen_random_uuid()")


def _enum(name: str) -> pg.ENUM:
    return pg.ENUM(*ENUMS[name], name=name, create_type=False)


def _app_role() -> str:
    role = context.config.attributes.get("app_role")
    if not isinstance(role, str) or not _IDENTIFIER.fullmatch(role):
        raise RuntimeError("app_role must be a plain PostgreSQL identifier; refusing to GRANT")
    return op.get_bind().dialect.identifier_preparer.quote(role)


def upgrade() -> None:
    bind = op.get_bind()
    for name, labels in ENUMS.items():
        pg.ENUM(*labels, name=name).create(bind, checkfirst=False)

    op.create_table(
        "detection_rules",
        sa.Column("id", UUID, primary_key=True, server_default=NEW_UUID),
        sa.Column("rule_id", sa.Text, nullable=False),
        sa.Column("name", sa.Text, nullable=False),
        sa.Column("version", sa.Integer, nullable=False),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default=sa.text("true")),
        sa.Column("base_severity", sa.SmallInteger, nullable=False),
        sa.Column("window_seconds", sa.Integer, nullable=False),
        sa.Column("params", pg.JSONB, nullable=False),
        sa.Column("description", sa.Text, nullable=False),
        sa.Column("mitre_hint", sa.Text, nullable=True),
        sa.Column("updated_at", TZ, nullable=False, server_default=NOW),
        sa.UniqueConstraint("rule_id", name="uq_detection_rules_rule_id"),
        sa.CheckConstraint(
            "base_severity BETWEEN 1 AND 5", name="ck_detection_rules_base_severity_range"
        ),
        sa.CheckConstraint("window_seconds > 0", name="ck_detection_rules_window_seconds_positive"),
        sa.CheckConstraint("version >= 1", name="ck_detection_rules_version_positive"),
    )
    op.create_table(
        "detector_runs",
        sa.Column("id", UUID, primary_key=True, server_default=NEW_UUID),
        sa.Column(
            "rule_id",
            UUID,
            sa.ForeignKey(
                "detection_rules.id",
                ondelete="CASCADE",
                name="fk_detector_runs_rule_id_detection_rules",
            ),
            nullable=False,
        ),
        sa.Column("window_start", TZ, nullable=False),
        sa.Column("window_end", TZ, nullable=False),
        sa.Column("events_examined", sa.Integer, nullable=False),
        sa.Column("alerts_created", sa.Integer, nullable=False),
        sa.Column("status", _enum("detector_run_status"), nullable=False),
        sa.Column("error_detail", sa.Text, nullable=True),
        sa.Column("duration_ms", sa.Integer, nullable=False),
        sa.Column("created_at", TZ, nullable=False, server_default=NOW),
        sa.CheckConstraint("window_end > window_start", name="ck_detector_runs_window_order"),
    )
    op.create_index("ix_detector_runs_created_at", "detector_runs", [sa.text("created_at DESC")])
    op.create_table(
        "alerts",
        sa.Column("id", UUID, primary_key=True, server_default=NEW_UUID),
        sa.Column(
            "rule_id",
            UUID,
            sa.ForeignKey(
                "detection_rules.id", ondelete="RESTRICT", name="fk_alerts_rule_id_detection_rules"
            ),
            nullable=False,
        ),
        sa.Column("rule_version", sa.Integer, nullable=False),
        sa.Column("dedup_key", sa.Text, nullable=False),
        sa.Column("severity", sa.SmallInteger, nullable=False),
        sa.Column("confidence", sa.Numeric(3, 2), nullable=False),
        sa.Column("severity_rationale", pg.JSONB, nullable=False),
        sa.Column("entity_type", _enum("entity_type"), nullable=False),
        sa.Column("entity_value", sa.Text, nullable=False),
        sa.Column("first_seen", TZ, nullable=False),
        sa.Column("last_seen", TZ, nullable=False),
        sa.Column("evidence", pg.JSONB, nullable=False),
        sa.Column("event_count", sa.Integer, nullable=False),
        sa.Column(
            "status", _enum("alert_status"), nullable=False, server_default=sa.text("'open'")
        ),
        sa.Column("created_at", TZ, nullable=False, server_default=NOW),
        sa.UniqueConstraint("dedup_key", name="uq_alerts_dedup_key"),
        sa.CheckConstraint("severity BETWEEN 1 AND 5", name="ck_alerts_severity_range"),
        sa.CheckConstraint("confidence BETWEEN 0 AND 1", name="ck_alerts_confidence_range"),
        sa.CheckConstraint("event_count >= 1", name="ck_alerts_event_count_positive"),
        sa.CheckConstraint("last_seen >= first_seen", name="ck_alerts_seen_order"),
    )
    op.create_index(
        "ix_alerts_severity_first_seen",
        "alerts",
        [sa.text("severity DESC"), sa.text("first_seen DESC")],
    )
    op.create_index("ix_alerts_entity", "alerts", ["entity_type", "entity_value", "first_seen"])
    op.create_index(
        "ix_alerts_first_seen_id", "alerts", [sa.text("first_seen DESC"), sa.text("id DESC")]
    )
    op.create_index("ix_alerts_evidence", "alerts", ["evidence"], postgresql_using="gin")
    op.create_table(
        "alert_events",
        sa.Column(
            "alert_id",
            UUID,
            sa.ForeignKey("alerts.id", ondelete="CASCADE", name="fk_alert_events_alert_id_alerts"),
            primary_key=True,
        ),
        sa.Column(
            "event_id",
            UUID,
            sa.ForeignKey("events.id", ondelete="CASCADE", name="fk_alert_events_event_id_events"),
            primary_key=True,
        ),
        sa.Column("role", _enum("alert_event_role"), nullable=False),
    )
    op.create_table(
        "alert_assets",
        sa.Column(
            "alert_id",
            UUID,
            sa.ForeignKey("alerts.id", ondelete="CASCADE", name="fk_alert_assets_alert_id_alerts"),
            primary_key=True,
        ),
        sa.Column(
            "asset_id",
            UUID,
            sa.ForeignKey("assets.id", ondelete="CASCADE", name="fk_alert_assets_asset_id_assets"),
            primary_key=True,
        ),
        sa.Column("role", _enum("alert_asset_role"), nullable=False),
    )
    op.create_table(
        "asset_baselines",
        sa.Column("id", UUID, primary_key=True, server_default=NEW_UUID),
        sa.Column(
            "asset_id",
            UUID,
            sa.ForeignKey(
                "assets.id", ondelete="CASCADE", name="fk_asset_baselines_asset_id_assets"
            ),
            nullable=False,
        ),
        sa.Column("metric", _enum("baseline_metric"), nullable=False),
        sa.Column("window_days", sa.Integer, nullable=False),
        sa.Column("mean", sa.Float, nullable=False),
        sa.Column("stddev", sa.Float, nullable=False),
        sa.Column("p95", sa.Float, nullable=False),
        sa.Column("sample_count", sa.Integer, nullable=False),
        sa.Column("computed_at", TZ, nullable=False, server_default=NOW),
        sa.UniqueConstraint(
            "asset_id", "metric", "window_days", name="uq_asset_baselines_asset_id"
        ),
        sa.CheckConstraint("window_days > 0", name="ck_asset_baselines_window_days_positive"),
    )

    role = _app_role()
    for table in TABLES_IN_ORDER:
        # Identifiers only: table names are literals from this file, the role is validated.
        op.execute(f"GRANT SELECT, INSERT, UPDATE ON TABLE {table} TO {role}")


def downgrade() -> None:
    bind = op.get_bind()
    for table in reversed(TABLES_IN_ORDER):
        op.drop_table(table)
    for name in reversed(tuple(ENUMS)):
        pg.ENUM(name=name).drop(bind, checkfirst=False)
