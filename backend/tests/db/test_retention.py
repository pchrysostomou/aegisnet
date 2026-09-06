"""Retention against PostgreSQL 16 (revision 0006; ADR-033).

Two claims are worth the price of a real database here, and neither can be checked anywhere
else: what the retention role may do, and what a prune leaves behind.

The first is a privilege matrix. The whole reason a third role exists is that `audit_log` and
the brief tables are append-only for the runtime role, and a retention policy is not a reason
to give that up — so the test that matters is the one asserting the retention role can delete
from four tables, cannot delete from any other, and cannot write a single row anywhere.

The second is the evidence rule. `alert_events.event_id` is `ON DELETE CASCADE`, so an over-
broad delete does not raise: it silently strips an alert of the events that produced it.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.exc import ProgrammingError
from sqlalchemy.ext.asyncio import AsyncEngine

from aegisnet.adapters.db.detection_store import SqlAlertStore, SqlRuleStore
from aegisnet.adapters.db.models import ALL_TABLES
from aegisnet.adapters.db.retention_store import SqlRetentionStore, UnknownRetentionTableError
from aegisnet.adapters.db.session import make_session_factory
from aegisnet.domain.enums import EntityType, SampleRole
from aegisnet.domain.ports import NewAlert
from aegisnet.domain.retention import AUDIT_LOG, DETECTOR_RUNS, EVENTS, INGEST_REJECTS

pytestmark = [pytest.mark.db, pytest.mark.integration]

NOW = datetime(2026, 9, 6, 12, 0, tzinfo=UTC)
OLD = NOW - timedelta(days=400)
RECENT = NOW - timedelta(days=1)
PRUNABLE = (EVENTS, INGEST_REJECTS, DETECTOR_RUNS, AUDIT_LOG)


@pytest.fixture(autouse=True)
async def clean(migrator_engine: AsyncEngine) -> AsyncIterator[None]:
    async with migrator_engine.begin() as connection:
        for table in ("alert_events", "alerts", "events", "ingest_rejects", "ingest_batches"):
            await connection.execute(text(f"DELETE FROM {table}"))  # noqa: S608 - fixed names
        await connection.execute(text("DELETE FROM audit_log"))
    yield


async def _batch(engine: AsyncEngine) -> UUID:
    batch_id = uuid4()
    async with engine.begin() as connection:
        await connection.execute(
            text(
                "INSERT INTO ingest_batches (id, status, source_type, source_label,"
                " ingest_method, started_at) VALUES (:id, 'complete', 'suricata_eve', 'test',"
                " 'registry_import', :now)"
            ),
            {"id": batch_id, "now": NOW},
        )
    return batch_id


async def _event(engine: AsyncEngine, batch_id: UUID, when: datetime) -> UUID:
    event_id = uuid4()
    async with engine.begin() as connection:
        await connection.execute(
            text(
                "INSERT INTO events (id, batch_id, event_time, event_type, event_hash,"
                " payload) VALUES (:id, :batch, :when, 'flow', :digest, '{}'::jsonb)"
            ),
            # `event_hash` is bytea with a 32-byte check constraint.
            {"id": event_id, "batch": batch_id, "when": when, "digest": uuid4().bytes * 2},
        )
    return event_id


# ---------------------------------------------------------------- the privilege matrix


async def test_the_retention_role_may_delete_from_exactly_four_tables(
    retention_engine: AsyncEngine,
) -> None:
    """The list is the decision. A fifth table appearing here without an ADR would mean a
    policy nobody wrote down."""
    async with retention_engine.connect() as connection:
        rows = await connection.execute(
            text(
                "SELECT table_name FROM information_schema.role_table_grants"
                " WHERE grantee = current_user AND privilege_type = 'DELETE'"
                " ORDER BY table_name"
            )
        )
        assert sorted(r[0] for r in rows) == sorted(PRUNABLE)


async def test_the_retention_role_reads_the_links_it_must_honour_and_cannot_delete_them(
    retention_engine: AsyncEngine,
) -> None:
    """The `events` rule keeps any event an alert points at, and the `NOT EXISTS` expressing
    that has to see `alert_events`. Read only: the links themselves are evidence."""
    async with retention_engine.connect() as connection:
        rows = await connection.execute(
            text(
                "SELECT privilege_type FROM information_schema.role_table_grants"
                " WHERE grantee = current_user AND table_name = 'alert_events'"
            )
        )
        assert sorted(r[0] for r in rows) == ["SELECT"]


async def test_the_retention_role_cannot_write_anything_anywhere(
    retention_engine: AsyncEngine,
) -> None:
    """It deletes and it reads. It has no way to add a row or change one, which is what makes
    it safe to hand the only DELETE in the deployment to."""
    async with retention_engine.connect() as connection:
        rows = await connection.execute(
            text(
                "SELECT DISTINCT privilege_type FROM information_schema.role_table_grants"
                " WHERE grantee = current_user ORDER BY privilege_type"
            )
        )
        assert sorted(r[0] for r in rows) == ["DELETE", "SELECT"]


async def test_the_retention_role_cannot_touch_a_case_or_a_brief(
    retention_engine: AsyncEngine,
) -> None:
    """The tables this project exists to produce are not reachable by the one role that can
    delete — not by policy, by grant."""
    async with retention_engine.connect() as connection:
        for table in ("incidents", "alerts", "investigation_briefs", "brief_citations"):
            nested = await connection.begin_nested()
            with pytest.raises(ProgrammingError) as refused:
                await connection.execute(text(f"DELETE FROM {table}"))  # noqa: S608 - fixed
            if nested.is_active:
                await nested.rollback()
            assert "permission denied" in str(refused.value), table


async def test_the_runtime_role_still_cannot_delete_the_audit_log(app_engine: AsyncEngine) -> None:
    """The property the third role exists to preserve. Adding retention must not have quietly
    widened what the application itself can do (T-2.5, ADR-012, ADR-031)."""
    async with app_engine.connect() as connection:
        for statement in ("DELETE FROM audit_log", "UPDATE audit_log SET action = 'x'"):
            nested = await connection.begin_nested()
            with pytest.raises(ProgrammingError) as refused:
                await connection.execute(text(statement))
            if nested.is_active:
                await nested.rollback()
            assert "permission denied" in str(refused.value), statement


async def test_no_table_is_prunable_without_being_in_the_policy(
    retention_engine: AsyncEngine,
) -> None:
    """Every DELETE grant corresponds to a rule, and every table exists in the schema."""
    assert set(PRUNABLE) <= set(ALL_TABLES)
    async with retention_engine.connect() as connection:
        rows = await connection.execute(
            text(
                "SELECT table_name FROM information_schema.role_table_grants"
                " WHERE grantee = current_user AND privilege_type = 'DELETE'"
            )
        )
        assert {r[0] for r in rows} == set(PRUNABLE)


# ---------------------------------------------------------------- what a prune leaves


async def test_an_event_an_alert_points_at_is_never_old_enough(
    migrator_engine: AsyncEngine, retention_engine: AsyncEngine
) -> None:
    """`alert_events.event_id` is ON DELETE CASCADE, so an over-broad prune does not fail — it
    removes an alert's evidence and leaves the alert standing with nothing behind it."""
    batch_id = await _batch(migrator_engine)
    linked = await _event(migrator_engine, batch_id, OLD)
    loose = await _event(migrator_engine, batch_id, OLD)
    fresh = await _event(migrator_engine, batch_id, RECENT)

    # Built through the real stores rather than by hand: the columns of `detection_rules` and
    # `alerts` are not this test's business, and guessing at them is how the first version of
    # it failed twice.
    sessions = make_session_factory(migrator_engine)
    await SqlRuleStore(sessions).upsert(
        rule_id="D-001",
        name="port scan",
        version=1,
        base_severity=3,
        window_seconds=600,
        params={},
        description="test",
        mitre_hint=None,
        now=NOW,
    )
    await SqlAlertStore(sessions).create_many(
        [
            NewAlert(
                rule_id="D-001",
                rule_version=1,
                dedup_key="D-001:retention",
                severity=3,
                confidence=0.8,
                severity_rationale={"result": 3},
                entity_type=EntityType.src_ip,
                entity_value="10.0.0.1",
                first_seen=OLD,
                last_seen=OLD,
                evidence={},
                event_count=1,
                samples=((linked, SampleRole.first),),
                assets=(),
            )
        ],
        NOW,
    )

    store = SqlRetentionStore(retention_engine)
    outcome = await store.prune(EVENTS, NOW - timedelta(days=90), batch=100, max_batches=5)

    assert outcome.removed == 1, "the loose old event, and only it"
    assert outcome.remaining == 0
    async with migrator_engine.connect() as connection:
        surviving = {row[0] for row in await connection.execute(text("SELECT id FROM events"))}
    assert linked in surviving, "the alert's evidence"
    assert fresh in surviving, "and anything inside the window"
    assert loose not in surviving


async def test_a_prune_removes_what_is_old_and_keeps_what_is_not(
    migrator_engine: AsyncEngine, retention_engine: AsyncEngine
) -> None:
    async with migrator_engine.begin() as connection:
        for index, when in ((1, OLD), (2, OLD), (3, RECENT)):
            await connection.execute(
                text(
                    "INSERT INTO audit_log (occurred_at, action, target_type, result, detail)"
                    " VALUES (:when, :action, 'test', 'success', '{}'::jsonb)"
                ),
                {"when": when, "action": f"test.{index}"},
            )

    store = SqlRetentionStore(retention_engine)
    before = NOW - timedelta(days=365)
    assert await store.count(AUDIT_LOG, before) == 2

    outcome = await store.prune(AUDIT_LOG, before, batch=100, max_batches=5)
    assert (outcome.removed, outcome.remaining) == (2, 0)
    assert await store.count(AUDIT_LOG, before) == 0

    async with migrator_engine.connect() as connection:
        rows = await connection.execute(text("SELECT action FROM audit_log ORDER BY action"))
        assert [r[0] for r in rows] == ["test.3"], "the recent row is untouched"


async def test_a_batch_ceiling_stops_a_run_and_says_what_is_left(
    migrator_engine: AsyncEngine, retention_engine: AsyncEngine
) -> None:
    """A first prune of a long-neglected table must finish rather than hold locks until
    somebody notices, so a run is allowed to leave work for tomorrow — and must say so."""
    async with migrator_engine.begin() as connection:
        for index in range(7):
            await connection.execute(
                text(
                    "INSERT INTO audit_log (occurred_at, action, target_type, result, detail)"
                    " VALUES (:when, :action, 'test', 'success', '{}'::jsonb)"
                ),
                {"when": OLD, "action": f"test.{index}"},
            )

    store = SqlRetentionStore(retention_engine)
    before = NOW - timedelta(days=365)
    outcome = await store.prune(AUDIT_LOG, before, batch=2, max_batches=2)

    assert outcome.removed == 4, "two passes of two"
    assert outcome.remaining == 3, "and it says what it did not reach"

    finishing = await store.prune(AUDIT_LOG, before, batch=2, max_batches=10)
    assert (finishing.removed, finishing.remaining) == (3, 0), "the next run picks up where it left"


async def test_a_table_with_no_statement_is_refused_rather_than_improvised(
    retention_engine: AsyncEngine,
) -> None:
    """Every statement is a literal chosen from a fixed map. A rule added without its SQL is a
    loud failure, not a query assembled from a variable."""
    store = SqlRetentionStore(retention_engine)
    with pytest.raises(UnknownRetentionTableError):
        await store.count("incidents", NOW)
    with pytest.raises(UnknownRetentionTableError):
        await store.prune("incidents", NOW, batch=10, max_batches=1)
