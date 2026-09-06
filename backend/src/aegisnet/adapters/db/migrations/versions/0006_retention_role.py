"""The retention role's only privileges (Milestone 6, Chunk 25; ADR-033).

No tables, no columns, no indexes — this revision exists to say what one role may do, and the
short list is the point:

    SELECT, DELETE on events, ingest_rejects, detector_runs, audit_log
    SELECT          on alert_events

and nothing else, anywhere. It cannot INSERT, it cannot UPDATE, and it cannot touch a case, an
alert or a brief. The read on `alert_events` is what lets the `events` rule keep an event an
alert still points at; without it the exclusion cannot be expressed at all.

The reason it exists at all is that `audit_log` and the two brief tables are **append-only for
the runtime role** — `SELECT, INSERT` and no more — and three decision records rest on that
(ADR-012, ADR-031, ADR-032). A retention policy needs somebody to be able to delete. Granting
that to the app role would end the property; giving it to a second role, whose credentials only
the retention job holds and which can write nothing at all, keeps it.

`SELECT` is included because a delete has to find its rows and because a dry run has to count
them without removing anything, which is the mode an operator should reach for first.

Revision ID: 0006_retention_role
Revises: 0005_brief_tables
Create Date: 2026-09-06
"""

from __future__ import annotations

import re
from collections.abc import Sequence

from alembic import context, op

revision: str = "0006_retention_role"
down_revision: str | None = "0005_brief_tables"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

RETENTION_TABLES: tuple[str, ...] = (
    "events",
    "ingest_rejects",
    "detector_runs",
    "audit_log",
)
"""Exactly the tables `domain/retention.rules()` gives a period. A table in one list and not
the other is a policy nobody wrote down, and `tests/db/test_retention.py` fails on it."""

READ_ONLY_TABLES: tuple[str, ...] = ("alert_events",)
"""Read, never delete. The `events` rule keeps any event an alert still points at, and the
`NOT EXISTS` that expresses it has to be able to see the link — a role that could not read
`alert_events` would either fail or, worse, be written without the exclusion. The database
suite found this by refusing the prune, which is the right way round."""

_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,62}$")


def _role(name: str) -> str:
    """The role name comes from settings and goes into SQL text, so it is validated against a
    plain-identifier pattern and quoted — the same guard every other revision uses."""
    value = context.config.attributes.get(name)
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise RuntimeError(f"{name} must be a plain PostgreSQL identifier; refusing to GRANT")
    return op.get_bind().dialect.identifier_preparer.quote(value)


def upgrade() -> None:
    retention = _role("retention_role")
    for table in RETENTION_TABLES:
        op.execute(f"GRANT SELECT, DELETE ON TABLE {table} TO {retention}")
    for table in READ_ONLY_TABLES:
        op.execute(f"GRANT SELECT ON TABLE {table} TO {retention}")


def downgrade() -> None:
    retention = _role("retention_role")
    for table in reversed(READ_ONLY_TABLES):
        op.execute(f"REVOKE SELECT ON TABLE {table} FROM {retention}")  # noqa: S608 - fixed names
    for table in reversed(RETENTION_TABLES):
        op.execute(f"REVOKE SELECT, DELETE ON TABLE {table} FROM {retention}")
