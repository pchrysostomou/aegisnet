"""The baseline revision creates exactly the documented schema, and the ORM agrees with it."""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from sqlalchemy import Connection, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine
from sqlalchemy.pool import NullPool

from aegisnet.adapters.db.models import M1_TABLES, Base
from aegisnet.config import Settings
from aegisnet.domain import enums
from aegisnet.version import schema_revision

pytestmark = [pytest.mark.db, pytest.mark.integration]

EXPECTED_ENUMS: dict[str, tuple[str, ...]] = {
    "source_type": tuple(enums.SourceType),
    "ingest_method": tuple(enums.IngestMethod),
    "ingest_status": tuple(enums.IngestStatus),
    "event_type": tuple(enums.EventType),
    "reject_reason": tuple(enums.RejectReason),
    "asset_environment": tuple(enums.AssetEnvironment),
    "user_role": tuple(enums.UserRole),
    "service_token_role": tuple(enums.ServiceTokenRole),
    "audit_result": tuple(enums.AuditResult),
}


def _table_names(connection: Connection) -> set[str]:
    return set(sa.inspect(connection).get_table_names())


async def _tables(engine: AsyncEngine) -> set[str]:
    async with engine.connect() as connection:
        return await connection.run_sync(_table_names)


async def _enum_labels(engine: AsyncEngine) -> dict[str, tuple[str, ...]]:
    query = text(
        "SELECT t.typname, e.enumlabel FROM pg_type t "
        "JOIN pg_enum e ON e.enumtypid = t.oid ORDER BY t.typname, e.enumsortorder"
    )
    async with engine.connect() as connection:
        rows = (await connection.execute(query)).all()
    labels: dict[str, list[str]] = {}
    for typname, label in rows:
        labels.setdefault(typname, []).append(label)
    return {name: tuple(values) for name, values in labels.items()}


async def test_baseline_creates_exactly_the_nine_tables(migrator_engine: AsyncEngine) -> None:
    assert await _tables(migrator_engine) == set(M1_TABLES) | {"alembic_version"}


async def test_alembic_version_matches_the_packaged_head(migrator_engine: AsyncEngine) -> None:
    async with migrator_engine.connect() as connection:
        applied = (await connection.execute(text("SELECT version_num FROM alembic_version"))).all()
    assert [row[0] for row in applied] == [schema_revision()] == ["0002_asset_network_delete_grant"]


async def test_orm_metadata_matches_the_migrated_schema(migrator_engine: AsyncEngine) -> None:
    """Alembic's own comparison finds no difference between models.py and the database."""

    def diff(connection: Connection) -> list[object]:
        context = MigrationContext.configure(connection, opts={"compare_type": True})
        return compare_metadata(context, Base.metadata)

    async with migrator_engine.connect() as connection:
        differences = await connection.run_sync(diff)
    assert differences == []


async def test_enum_types_carry_the_documented_labels(migrator_engine: AsyncEngine) -> None:
    assert await _enum_labels(migrator_engine) == EXPECTED_ENUMS


@pytest.mark.parametrize(
    ("index", "table", "fragments"),
    [
        ("ix_asset_networks_cidr", "asset_networks", ("USING gist", "inet_ops")),
        ("ix_events_payload", "events", ("USING gin", "jsonb_path_ops")),
        ("ix_assets_tags", "assets", ("USING gin",)),
        ("ix_events_flow_id", "events", ("WHERE (flow_id IS NOT NULL)",)),
        ("ix_events_event_time", "events", ("event_time DESC",)),
    ],
)
async def test_specialised_indexes_are_built_as_documented(
    migrator_engine: AsyncEngine, index: str, table: str, fragments: tuple[str, ...]
) -> None:
    query = text("SELECT indexdef FROM pg_indexes WHERE tablename = :t AND indexname = :i")
    async with migrator_engine.connect() as connection:
        definition = (await connection.execute(query, {"t": table, "i": index})).scalar_one()
    for fragment in fragments:
        assert fragment in definition, definition


async def test_event_hash_must_be_thirty_two_bytes_and_unique(app_engine: AsyncEngine) -> None:
    now = datetime.now(tz=UTC)
    async with app_engine.connect() as connection:
        transaction = await connection.begin()
        batch_id = (
            await connection.execute(
                text(
                    "INSERT INTO ingest_batches (source_type, source_label, ingest_method) "
                    "VALUES ('suricata_eve', 'test', 'api_ndjson') RETURNING id"
                )
            )
        ).scalar_one()
        insert = text(
            "INSERT INTO events (batch_id, event_hash, event_time, event_type, payload) "
            "VALUES (:b, :h, :t, 'dns', '{}'::jsonb)"
        )
        good = {"b": batch_id, "h": b"\x01" * 32, "t": now}

        nested = await connection.begin_nested()
        with pytest.raises(IntegrityError, match="ck_events_event_hash_length"):
            await connection.execute(insert, {**good, "h": b"\x01" * 31})
        await nested.rollback()

        await connection.execute(insert, good)
        nested = await connection.begin_nested()
        with pytest.raises(IntegrityError, match="uq_events_event_hash"):
            await connection.execute(insert, good)
        await nested.rollback()

        await transaction.rollback()


async def test_email_is_unique_regardless_of_case(app_engine: AsyncEngine) -> None:
    insert = text(
        "INSERT INTO users (email, display_name, password_hash, role) "
        "VALUES (:e, 'x', 'argon2id$placeholder', 'viewer')"
    )
    async with app_engine.connect() as connection:
        transaction = await connection.begin()
        await connection.execute(insert, {"e": "Analyst@Example.test"})
        nested = await connection.begin_nested()
        with pytest.raises(IntegrityError, match="uq_users_email"):
            await connection.execute(insert, {"e": "analyst@example.TEST"})
        await nested.rollback()
        await transaction.rollback()


async def test_uuid_and_timestamp_defaults_are_server_generated(app_engine: AsyncEngine) -> None:
    async with app_engine.connect() as connection:
        transaction = await connection.begin()
        row = (
            await connection.execute(
                text(
                    "INSERT INTO assets (environment) VALUES ('lab') "
                    "RETURNING id, criticality, tags, is_active, created_at"
                )
            )
        ).one()
        await transaction.rollback()
    assert isinstance(row.id, uuid.UUID)
    assert row.criticality == 3
    assert row.tags == []
    assert row.is_active is True
    assert row.created_at.tzinfo is not None


def test_downgrade_to_base_leaves_nothing_behind(db_settings: Settings, migrated: Config) -> None:
    """Round trip: head → base removes every table, enum type and the citext extension;
    base → head restores the schema for the remaining tests. Alembic keeps its own, now
    empty, ``alembic_version`` table at base; that is the only object allowed to remain."""

    async def snapshot() -> tuple[set[str], set[str], bool, list[str]]:
        engine = create_async_engine(db_settings.migration_url, poolclass=NullPool)
        try:
            tables = await _tables(engine)
            enum_names = set(await _enum_labels(engine))
            async with engine.connect() as connection:
                citext = (
                    await connection.execute(
                        text("SELECT count(*) FROM pg_extension WHERE extname = 'citext'")
                    )
                ).scalar_one()
                versions = (
                    (await connection.execute(text("SELECT version_num FROM alembic_version")))
                    .scalars()
                    .all()
                )
            return tables, enum_names, bool(citext), list(versions)
        finally:
            await engine.dispose()

    command.downgrade(migrated, "base")
    try:
        tables, enum_names, citext, versions = asyncio.run(snapshot())
        assert tables == {"alembic_version"}
        assert versions == []
        assert enum_names == set()
        assert citext is False
    finally:
        command.upgrade(migrated, "head")

    tables, enum_names, citext, versions = asyncio.run(snapshot())
    assert tables == set(M1_TABLES) | {"alembic_version"}
    assert versions == ["0002_asset_network_delete_grant"]
    assert enum_names == set(EXPECTED_ENUMS)
    assert citext is True
