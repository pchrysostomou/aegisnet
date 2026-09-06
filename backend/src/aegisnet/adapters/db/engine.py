"""Thin async SQLAlchemy engine wiring.

One engine per credential *and per workload*. `create_engine_for` exists because the retention
job connects as a different role that can delete and cannot write (ADR-033), and a reader
should be able to see which is which.

There is deliberately no `create_engine(settings)` any more, and no default statement timeout.
Two workloads share one principal here — the API, the four actors and the CLI all connect as
`aegisnet_app` — so a single number cannot serve both: anything loose enough for a 200 000-event
sweep load is far too loose to bound a request (T-2.6). `create_api_engine` and
`create_job_engine` say which budget a call site is asking for, and the keyword is required, so
a new call site has to answer the question rather than inherit an answer. A default is exactly
how this gap would re-open.
"""

from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.engine import URL
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine
from sqlalchemy.pool import Pool

from aegisnet.config import Settings
from aegisnet.logging import get_logger

logger = get_logger(__name__)


def create_api_engine(settings: Settings) -> AsyncEngine:
    """The request path: a statement that outlives a person's patience is a bug, not a query."""
    return create_engine_for(
        settings.database_url, statement_timeout_ms=settings.db_statement_timeout_ms
    )


def create_job_engine(settings: Settings) -> AsyncEngine:
    """The worker, the CLI and the retention prune, which legitimately do more work per
    statement than a request ever should."""
    return create_engine_for(
        settings.database_url, statement_timeout_ms=settings.db_job_statement_timeout_ms
    )


def create_engine_for(
    url: URL, *, statement_timeout_ms: int, poolclass: type[Pool] | None = None
) -> AsyncEngine:
    """One engine, one credential, one statement budget.

    `statement_timeout_ms` is required and `0` means *no* timeout — which only the migrator
    asks for, and asks for explicitly: a migration that builds a GIST index over a populated
    `events` table must never be cancelled half way, and writing the zero down makes that a
    stated guarantee rather than an accident of the server default.

    It travels in the connection startup packet as an asyncpg `server_settings` entry, so it
    costs no round trip and is set once per pooled connection. A bare number is milliseconds to
    PostgreSQL.

    `poolclass` exists for the migrator, which uses `NullPool`; that pool takes no sizing
    arguments, so they are only passed when it is not in play.
    """
    options: dict[str, object] = {
        "pool_pre_ping": True,
        "pool_recycle": 1800,
        "echo": False,  # never echo SQL; it would log untrusted values
        # The companion to `echo=False`: keeps untrusted bound values out of the string form of
        # any DBAPIError, which is what a timeout produces and what a log line would carry.
        "hide_parameters": True,
    }
    if poolclass is None:
        options["pool_size"] = 5
        options["max_overflow"] = 5
    else:
        options["poolclass"] = poolclass
    if statement_timeout_ms:
        options["connect_args"] = {
            "server_settings": {"statement_timeout": str(statement_timeout_ms)}
        }
    return create_async_engine(url, **options)


async def ping(engine: AsyncEngine) -> bool:
    """Return True when a trivial round trip succeeds. Exceptions propagate to the caller."""
    async with engine.connect() as connection:
        result = await connection.execute(text("SELECT 1"))
        # scalar_one() is untyped, so the comparison must be narrowed explicitly.
        return bool(result.scalar_one() == 1)


async def dispose(engine: AsyncEngine) -> None:
    await engine.dispose()
