"""The two brief tables (Milestone 5, Chunk 23; docs/data-model.md; ADR-029 to ADR-031).

``investigation_briefs`` is one attempt at a narrative about one case, and ``brief_citations``
holds the sources it pointed at. Both are **append-only for the runtime role**: SELECT and
INSERT, no UPDATE and no DELETE, which is the same grant the audit log has and for the same
reason. A brief is a record of what a model said at a moment, next to a record of exactly what
was sent to get it; a brief that can be edited afterwards is not evidence of anything.

Versioning follows from that. Regenerating produces a new row with the next version rather than
replacing one, so an analyst can see that the first answer was refused and why.

A failed attempt is stored too. `status = 'failed'` with a `failure_reason` is what makes "the
API was down" visible instead of looking like nobody ever asked.

Revision ID: 0005_brief_tables
Revises: 0004_incident_tables
Create Date: 2026-09-06
"""

from __future__ import annotations

import re
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import context, op
from sqlalchemy.dialects import postgresql as pg

revision: str = "0005_brief_tables"
down_revision: str | None = "0004_incident_tables"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

ENUMS: dict[str, tuple[str, ...]] = {
    "brief_status": ("complete", "failed"),
    "brief_source": ("perplexity", "offline_fixture"),
}
TABLES_IN_ORDER: tuple[str, ...] = ("investigation_briefs", "brief_citations")
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
        "investigation_briefs",
        sa.Column("id", UUID, primary_key=True, server_default=NEW_UUID),
        sa.Column(
            "incident_id",
            UUID,
            sa.ForeignKey(
                "incidents.id",
                ondelete="CASCADE",
                name="fk_investigation_briefs_incident_id_incidents",
            ),
            nullable=False,
        ),
        sa.Column("version", sa.Integer, nullable=False),
        sa.Column("status", _enum("brief_status"), nullable=False),
        sa.Column("source", _enum("brief_source"), nullable=False),
        # Exactly what was sent, content-addressed. Two briefs with the same hash were asked
        # the same question, which is what makes a regeneration comparable.
        sa.Column("packet_hash", sa.Text, nullable=False),
        sa.Column("packet_truncated", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("model", sa.Text, nullable=True),
        sa.Column("summary", sa.Text, nullable=True),
        sa.Column("limitations", sa.Text, nullable=True),
        sa.Column("claims", pg.JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column(
            "recommendations", pg.JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")
        ),
        sa.Column("has_unverified", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("failure_reason", sa.Text, nullable=True),
        sa.Column("prompt_tokens", sa.Integer, nullable=True),
        sa.Column("completion_tokens", sa.Integer, nullable=True),
        sa.Column(
            "requested_by",
            UUID,
            sa.ForeignKey(
                "users.id", ondelete="SET NULL", name="fk_investigation_briefs_requested_by_users"
            ),
            nullable=True,
        ),
        sa.Column("created_at", TZ, nullable=False, server_default=NOW),
        # Versions are per case and allocated by the store, so two concurrent requests cannot
        # both take the same number.
        sa.UniqueConstraint("incident_id", "version", name="uq_investigation_briefs_version"),
        sa.CheckConstraint("version >= 1", name="ck_investigation_briefs_version_positive"),
        # A complete brief has something to say; a failed one says why it has not.
        sa.CheckConstraint(
            "(status = 'complete') = (summary IS NOT NULL)",
            name="ck_investigation_briefs_summary_matches_status",
        ),
        sa.CheckConstraint(
            "(status = 'failed') = (failure_reason IS NOT NULL)",
            name="ck_investigation_briefs_reason_matches_status",
        ),
    )
    op.create_index(
        "ix_investigation_briefs_incident",
        "investigation_briefs",
        ["incident_id", sa.text("version DESC")],
    )

    op.create_table(
        "brief_citations",
        sa.Column("id", UUID, primary_key=True, server_default=NEW_UUID),
        sa.Column(
            "brief_id",
            UUID,
            sa.ForeignKey(
                "investigation_briefs.id",
                ondelete="CASCADE",
                name="fk_brief_citations_brief_id_investigation_briefs",
            ),
            nullable=False,
        ),
        # The number the model used to refer to it from a claim.
        sa.Column("citation_id", sa.Integer, nullable=False),
        sa.Column("url", sa.Text, nullable=False),
        sa.Column("title", sa.Text, nullable=False),
        sa.Column("created_at", TZ, nullable=False, server_default=NOW),
        sa.UniqueConstraint("brief_id", "citation_id", name="uq_brief_citations_citation_id"),
        # https is enforced in the domain before it ever reaches here; the database says it too,
        # because a citation is a link somebody will click.
        sa.CheckConstraint("url LIKE 'https://%'", name="ck_brief_citations_https"),
    )
    op.create_index("ix_brief_citations_brief_id", "brief_citations", ["brief_id"])

    role = _app_role()
    for table in TABLES_IN_ORDER:
        # SELECT and INSERT only. A brief is immutable: regenerating writes a new version, and
        # nothing in the application may edit what a model said or what was sent to get it.
        op.execute(f"GRANT SELECT, INSERT ON TABLE {table} TO {role}")


def downgrade() -> None:
    bind = op.get_bind()
    for table in reversed(TABLES_IN_ORDER):
        op.drop_table(table)
    for name in reversed(tuple(ENUMS)):
        pg.ENUM(name=name).drop(bind, checkfirst=False)
