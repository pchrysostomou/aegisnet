"""T-5.3 / T-2.5: the runtime role can neither alter the schema nor rewrite the audit log.

The migrator owns every object. The app role holds SELECT, INSERT and UPDATE on the
ordinary tables, SELECT and INSERT on ``audit_log``, and nothing else: no DELETE anywhere,
no DDL. The catalogue is asserted for the whole matrix, and the audit-log guarantee is then
proven behaviourally by attempting the forbidden statements.
"""

from __future__ import annotations

import pytest
from sqlalchemy import text
from sqlalchemy.exc import ProgrammingError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from aegisnet.adapters.db.models import (
    ALL_TABLES,
    APP_ROLE_DELETE_TABLES,
    APP_ROLE_READ_WRITE_TABLES,
)
from aegisnet.config import Settings

pytestmark = [pytest.mark.db, pytest.mark.security]

PRIVILEGES = ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER")


async def _privileges(connection: AsyncConnection, table: str) -> set[str]:
    granted: set[str] = set()
    for privilege in PRIVILEGES:
        held = (
            await connection.execute(
                text("SELECT has_table_privilege(current_user, :t, :p)"),
                {"t": table, "p": privilege},
            )
        ).scalar_one()
        if held:
            granted.add(privilege)
    return granted


async def _expect_denied(connection: AsyncConnection, statement: str) -> None:
    nested = await connection.begin_nested()
    with pytest.raises(ProgrammingError) as excinfo:
        await connection.execute(text(statement))
    if nested.is_active:
        await nested.rollback()
    message = str(excinfo.value)
    assert "permission denied" in message or "must be owner" in message, message


async def test_app_role_privilege_matrix(app_engine: AsyncEngine) -> None:
    async with app_engine.connect() as connection:
        for table in APP_ROLE_READ_WRITE_TABLES:
            expected = {"SELECT", "INSERT", "UPDATE"}
            if table in APP_ROLE_DELETE_TABLES:
                expected.add("DELETE")
            assert await _privileges(connection, table) == expected, table
        assert await _privileges(connection, "audit_log") == {"SELECT", "INSERT"}
        assert await _privileges(connection, "alembic_version") == {"SELECT"}


async def test_migrator_owns_every_table(
    migrator_engine: AsyncEngine, db_settings: Settings
) -> None:
    query = text("SELECT tablename, tableowner FROM pg_tables WHERE schemaname = 'public'")
    async with migrator_engine.connect() as connection:
        owners = dict((await connection.execute(query)).all())
    assert set(owners) == set(ALL_TABLES) | {"alembic_version"}
    assert set(owners.values()) == {db_settings.postgres_migrator_user}


async def test_app_role_can_append_to_and_read_the_audit_log(app_engine: AsyncEngine) -> None:
    async with app_engine.connect() as connection:
        transaction = await connection.begin()
        row_id = (
            await connection.execute(
                text(
                    "INSERT INTO audit_log (action, target_type, result) "
                    "VALUES ('test.grants', 'test', 'success') RETURNING id"
                )
            )
        ).scalar_one()
        found = (
            await connection.execute(
                text("SELECT action FROM audit_log WHERE id = :i"), {"i": row_id}
            )
        ).scalar_one()
        await transaction.rollback()
    assert isinstance(row_id, int)
    assert found == "test.grants"


async def test_app_role_cannot_rewrite_or_erase_audit_rows(app_engine: AsyncEngine) -> None:
    async with app_engine.connect() as connection:
        transaction = await connection.begin()
        await connection.execute(
            text(
                "INSERT INTO audit_log (action, target_type, result) "
                "VALUES ('test.grants', 'test', 'success')"
            )
        )
        await _expect_denied(connection, "UPDATE audit_log SET action = 'forged'")
        await _expect_denied(connection, "DELETE FROM audit_log")
        await _expect_denied(connection, "TRUNCATE audit_log")
        await transaction.rollback()


async def test_app_role_has_no_delete_except_on_asset_networks(app_engine: AsyncEngine) -> None:
    async with app_engine.connect() as connection:
        transaction = await connection.begin()
        for table in ALL_TABLES:
            if table in APP_ROLE_DELETE_TABLES:
                continue
            await _expect_denied(connection, f"DELETE FROM {table}")  # noqa: S608 - literal names
        await connection.execute(text("DELETE FROM asset_networks WHERE false"))
        await transaction.rollback()


async def test_app_role_cannot_change_the_schema(app_engine: AsyncEngine) -> None:
    async with app_engine.connect() as connection:
        transaction = await connection.begin()
        await _expect_denied(connection, "CREATE TABLE smuggled (id int)")
        await _expect_denied(connection, "ALTER TABLE events ADD COLUMN extra text")
        await _expect_denied(connection, "DROP TABLE audit_log")
        await _expect_denied(connection, "ALTER TABLE audit_log OWNER TO CURRENT_USER")
        await _expect_denied(connection, "CREATE EXTENSION IF NOT EXISTS pg_trgm")
        await transaction.rollback()
