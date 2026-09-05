"""Grant DELETE on asset_networks to the runtime role.

Revision ID: 0002_asset_network_delete_grant
Revises: 0001_m1_baseline
Create Date: 2026-09-05

An asset's networks are attributes that ``PATCH /assets/{id}`` replaces wholesale
(Chunk 5, ADR-015). The baseline granted no DELETE anywhere; this is the first and, so
far, only table where the runtime role may remove rows. ``audit_log`` and ``events`` stay
append-only for the runtime role.
"""

from __future__ import annotations

import re
from collections.abc import Sequence

from alembic import context, op

revision: str = "0002_asset_network_delete_grant"
down_revision: str | None = "0001_m1_baseline"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,62}$")


def _app_role() -> str:
    role = context.config.attributes.get("app_role")
    if not isinstance(role, str) or not _IDENTIFIER.fullmatch(role):
        raise RuntimeError("app_role must be a plain PostgreSQL identifier; refusing to GRANT")
    return op.get_bind().dialect.identifier_preparer.quote(role)


def upgrade() -> None:
    op.execute(f"GRANT DELETE ON TABLE asset_networks TO {_app_role()}")


def downgrade() -> None:
    op.execute(f"REVOKE DELETE ON TABLE asset_networks FROM {_app_role()}")
