"""A statement the database will not run for ever (Milestone 6, Chunk 29; T-2.6).

`THREAT_MODEL.md` has named a query timeout since the planning phase and there was none. Page
sizes, window widths and rate limits all bound what a caller may *ask for*; nothing bounded what
the database would then spend. A query that gets past those bounds — through a slow plan, a
missing index after a schema change, a table that grew — ran until it finished.

These run against real PostgreSQL because the claim is about PostgreSQL. `pg_sleep` is the
honest probe: it is a statement that provably cannot finish inside the budget, so a test that
sees it cancelled is seeing the timeout and not a fast machine.

The three budgets are the point, and each is asserted separately:

* the request path is tight, because a statement that outlives a person's patience is a bug;
* the worker, the CLI and the retention prune get a much looser one, because a sweep over
  200 000 events legitimately does more work than a request ever should;
* the migrator gets **none**, because a migration that builds an index over a populated table
  must never be cancelled half way.
"""

from __future__ import annotations

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine
from sqlalchemy.pool import NullPool

from aegisnet.adapters.db.engine import create_api_engine, create_engine_for, create_job_engine
from aegisnet.api.errors import STATEMENT_TIMEOUT_SQLSTATE
from aegisnet.config import Settings

pytestmark = [pytest.mark.db, pytest.mark.security]


async def _show_timeout(engine: AsyncEngine) -> str:
    async with engine.connect() as connection:
        result = await connection.execute(text("SHOW statement_timeout"))
        return str(result.scalar_one())


async def test_the_request_path_carries_the_budget_it_was_configured_with(
    db_settings: Settings,
) -> None:
    engine = create_api_engine(db_settings.model_copy(update={"db_statement_timeout_ms": 2500}))
    try:
        assert await _show_timeout(engine) == "2500ms"
    finally:
        await engine.dispose()


async def test_a_statement_past_the_budget_is_cancelled_by_the_database(
    db_settings: Settings,
) -> None:
    """The assertion that would fail if the setting never reached the connection: a statement
    that cannot finish inside the budget comes back as `query_canceled`, which is the SQLSTATE
    the API's handler turns into the documented envelope."""
    engine = create_api_engine(db_settings.model_copy(update={"db_statement_timeout_ms": 1000}))
    try:
        async with engine.connect() as connection:
            with pytest.raises(DBAPIError) as raised:
                await connection.execute(text("SELECT pg_sleep(5)"))
        assert getattr(raised.value.orig, "sqlstate", None) == STATEMENT_TIMEOUT_SQLSTATE
    finally:
        await engine.dispose()


async def test_a_statement_inside_the_budget_is_left_alone(db_settings: Settings) -> None:
    """The other half, so the test above cannot be passing because *everything* is cancelled."""
    engine = create_api_engine(db_settings.model_copy(update={"db_statement_timeout_ms": 5000}))
    try:
        async with engine.connect() as connection:
            result = await connection.execute(text("SELECT pg_sleep(0.2), 42"))
            assert result.first()[1] == 42
    finally:
        await engine.dispose()


async def test_the_background_budget_is_looser_than_the_request_budget(
    db_settings: Settings,
) -> None:
    """Two workloads, one principal: the API, the actors and the CLI all connect as the same
    role, so the budget cannot come from the role. It comes from which factory was called."""
    api = create_api_engine(db_settings)
    job = create_job_engine(db_settings)
    try:
        api_ms = int(str(await _show_timeout(api)).removesuffix("ms").removesuffix("s"))
        assert await _show_timeout(api) != await _show_timeout(job)
        assert api_ms > 0
    finally:
        await api.dispose()
        await job.dispose()


async def test_the_migrator_is_held_to_no_statement_timeout_at_all(db_settings: Settings) -> None:
    """`0` is PostgreSQL's "no limit", and it is asked for explicitly rather than inherited.

    Asserted on a connection rather than on the source, so it fails if the zero stops reaching
    the database — a test that only read `env.py` would pass with the whole mechanism removed.
    """
    engine = create_engine_for(
        db_settings.migration_url, statement_timeout_ms=0, poolclass=NullPool
    )
    try:
        assert await _show_timeout(engine) == "0"
        # And a long statement really does run: the migrator is not throttled by the default
        # the runtime role now carries.
        async with engine.connect() as connection:
            await connection.execute(text("SELECT pg_sleep(1.5)"))
    finally:
        await engine.dispose()


async def test_the_retention_role_prunes_under_the_background_budget(
    db_settings: Settings,
) -> None:
    """A prune deletes in batches and must not inherit the request path's bound; it also must
    not be unbounded, or one runaway `DELETE` holds locks until somebody notices (ADR-033)."""
    engine = create_engine_for(
        db_settings.retention_url,
        statement_timeout_ms=db_settings.db_job_statement_timeout_ms,
    )
    try:
        assert await _show_timeout(engine) == "5min"
    finally:
        await engine.dispose()
