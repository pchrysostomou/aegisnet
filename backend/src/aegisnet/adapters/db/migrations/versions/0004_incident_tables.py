"""The four incident tables (Milestone 3, Chunk 15; docs/data-model.md; ADR-023).

``incidents`` is the case: the entity that grouped it, the window its alerts span, the
severity with the arithmetic that produced it, and a status that only moves along the paths
in ``domain/incidents.py``. ``incident_alerts`` links alerts to cases with a composite key, so
re-running correlation adds nothing twice. ``incident_timeline`` is the append-only story, and
``incident_notes`` is what an analyst wrote on it.

A case number comes from ``incident_case_seq`` rather than from a count, because two runs
allocating "the next one" at the same moment must not both get it. The runtime role gets
SELECT, INSERT and UPDATE on the tables and USAGE on the sequence; no DELETE (ADR-012).

Revision ID: 0004_incident_tables
Revises: 0003_detection_tables
Create Date: 2026-09-06
"""

from __future__ import annotations

import re
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import context, op
from sqlalchemy.dialects import postgresql as pg

revision: str = "0004_incident_tables"
down_revision: str | None = "0003_detection_tables"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

ENUMS: dict[str, tuple[str, ...]] = {
    "incident_status": (
        "new",
        "triaging",
        "investigating",
        "contained_recommended",
        "closed_true_positive",
        "closed_false_positive",
        "closed_benign",
    ),
    "timeline_entry_type": (
        "alert_fired",
        "observation",
        "status_change",
        "note_added",
        "brief_generated",
        "report_exported",
        "asset_linked",
    ),
    "incident_alert_source": ("correlation_engine", "analyst"),
}
TABLES_IN_ORDER: tuple[str, ...] = (
    "incidents",
    "incident_alerts",
    "incident_timeline",
    "incident_notes",
)
CASE_SEQUENCE = "incident_case_seq"
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
    op.execute(sa.text(f"CREATE SEQUENCE {CASE_SEQUENCE} AS bigint START WITH 1 INCREMENT BY 1"))

    op.create_table(
        "incidents",
        sa.Column("id", UUID, primary_key=True, server_default=NEW_UUID),
        sa.Column("case_number", sa.Text, nullable=False),
        sa.Column("title", sa.Text, nullable=False),
        sa.Column("severity", sa.SmallInteger, nullable=False),
        sa.Column("severity_rationale", pg.JSONB, nullable=False),
        sa.Column("status", _enum("incident_status"), nullable=False, server_default="new"),
        sa.Column(
            "primary_asset_id",
            UUID,
            sa.ForeignKey(
                "assets.id", ondelete="SET NULL", name="fk_incidents_primary_asset_id_assets"
            ),
            nullable=True,
        ),
        sa.Column("correlation_key", sa.Text, nullable=False),
        sa.Column("window_start", TZ, nullable=False),
        sa.Column("window_end", TZ, nullable=False),
        sa.Column("distinct_rule_count", sa.Integer, nullable=False),
        sa.Column(
            "assigned_to",
            UUID,
            sa.ForeignKey("users.id", ondelete="SET NULL", name="fk_incidents_assigned_to_users"),
            nullable=True,
        ),
        sa.Column("closed_at", TZ, nullable=True),
        sa.Column("closure_reason", sa.Text, nullable=True),
        sa.Column("created_at", TZ, nullable=False, server_default=NOW),
        sa.Column("updated_at", TZ, nullable=False, server_default=NOW),
        sa.UniqueConstraint("case_number", name="uq_incidents_case_number"),
        sa.CheckConstraint("severity BETWEEN 1 AND 5", name="ck_incidents_severity_range"),
        sa.CheckConstraint("window_end >= window_start", name="ck_incidents_window_order"),
        sa.CheckConstraint(
            "distinct_rule_count >= 1", name="ck_incidents_distinct_rule_count_positive"
        ),
        # A closed case carries the moment it closed, and an open one does not pretend to.
        sa.CheckConstraint(
            "(status IN ('closed_true_positive', 'closed_false_positive', 'closed_benign'))"
            " = (closed_at IS NOT NULL)",
            name="ck_incidents_closed_at_matches_status",
        ),
    )
    op.create_index("ix_incidents_created_at", "incidents", [sa.text("created_at DESC")])
    op.create_index("ix_incidents_status", "incidents", ["status"])
    # The lookup correlation makes on every run: the open case for this entity, most recent
    # first. Partial, because a closed case never absorbs a new alert (ADR-023).
    op.create_index(
        "ix_incidents_open_by_key",
        "incidents",
        ["correlation_key", sa.text("window_end DESC")],
        postgresql_where=sa.text(
            "status NOT IN ('closed_true_positive', 'closed_false_positive', 'closed_benign')"
        ),
    )

    op.create_table(
        "incident_alerts",
        sa.Column(
            "incident_id",
            UUID,
            sa.ForeignKey(
                "incidents.id", ondelete="CASCADE", name="fk_incident_alerts_incident_id_incidents"
            ),
            primary_key=True,
        ),
        sa.Column(
            "alert_id",
            UUID,
            sa.ForeignKey(
                "alerts.id", ondelete="CASCADE", name="fk_incident_alerts_alert_id_alerts"
            ),
            primary_key=True,
        ),
        sa.Column("added_at", TZ, nullable=False, server_default=NOW),
        sa.Column("added_by", _enum("incident_alert_source"), nullable=False),
        # One alert belongs to one case. Without this an alert could be counted twice and a
        # correlation re-run could quietly fan a case out into several.
        sa.UniqueConstraint("alert_id", name="uq_incident_alerts_alert_id"),
    )

    op.create_table(
        "incident_timeline",
        sa.Column("id", UUID, primary_key=True, server_default=NEW_UUID),
        sa.Column(
            "incident_id",
            UUID,
            sa.ForeignKey(
                "incidents.id",
                ondelete="CASCADE",
                name="fk_incident_timeline_incident_id_incidents",
            ),
            nullable=False,
        ),
        sa.Column("occurred_at", TZ, nullable=False),
        sa.Column("entry_type", _enum("timeline_entry_type"), nullable=False),
        sa.Column("summary", sa.Text, nullable=False),
        sa.Column("detail", pg.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column(
            "actor_user_id",
            UUID,
            sa.ForeignKey(
                "users.id", ondelete="SET NULL", name="fk_incident_timeline_actor_user_id_users"
            ),
            nullable=True,
        ),
        sa.Column(
            "alert_id",
            UUID,
            sa.ForeignKey(
                "alerts.id", ondelete="SET NULL", name="fk_incident_timeline_alert_id_alerts"
            ),
            nullable=True,
        ),
        sa.Column("created_at", TZ, nullable=False, server_default=NOW),
        # An alert appears once in a case's story; re-running correlation says nothing new.
        sa.UniqueConstraint(
            "incident_id", "entry_type", "alert_id", name="uq_incident_timeline_alert_entry"
        ),
    )
    op.create_index(
        "ix_incident_timeline_incident_id", "incident_timeline", ["incident_id", "occurred_at"]
    )

    op.create_table(
        "incident_notes",
        sa.Column("id", UUID, primary_key=True, server_default=NEW_UUID),
        sa.Column(
            "incident_id",
            UUID,
            sa.ForeignKey(
                "incidents.id", ondelete="CASCADE", name="fk_incident_notes_incident_id_incidents"
            ),
            nullable=False,
        ),
        sa.Column(
            "author_id",
            UUID,
            sa.ForeignKey(
                "users.id", ondelete="SET NULL", name="fk_incident_notes_author_id_users"
            ),
            nullable=True,
        ),
        sa.Column("body", sa.Text, nullable=False),
        sa.Column("created_at", TZ, nullable=False, server_default=NOW),
        sa.CheckConstraint("length(body) BETWEEN 1 AND 8000", name="ck_incident_notes_body_length"),
    )
    op.create_index(
        "ix_incident_notes_incident_id", "incident_notes", ["incident_id", "created_at"]
    )

    role = _app_role()
    for table in TABLES_IN_ORDER:
        # Identifiers only: table names are literals from this file, the role is validated.
        op.execute(f"GRANT SELECT, INSERT, UPDATE ON TABLE {table} TO {role}")
    op.execute(f"GRANT USAGE ON SEQUENCE {CASE_SEQUENCE} TO {role}")


def downgrade() -> None:
    bind = op.get_bind()
    for table in reversed(TABLES_IN_ORDER):
        op.drop_table(table)
    op.execute(sa.text(f"DROP SEQUENCE {CASE_SEQUENCE}"))
    for name in reversed(tuple(ENUMS)):
        pg.ENUM(name=name).drop(bind, checkfirst=False)
