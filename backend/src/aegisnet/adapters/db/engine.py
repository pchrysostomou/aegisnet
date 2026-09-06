"""Thin async SQLAlchemy engine wiring.

One engine per credential. `create_engine` is the runtime role, which everything uses;
`create_engine_for` exists because the retention job connects as a different role that can
delete and cannot write (ADR-033), and a reader should be able to see which is which.
"""

from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.engine import URL
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from aegisnet.config import Settings
from aegisnet.logging import get_logger

logger = get_logger(__name__)


def create_engine(settings: Settings) -> AsyncEngine:
    """The runtime role's engine — everything the API and the worker do."""
    return create_engine_for(settings.database_url)


def create_engine_for(url: URL) -> AsyncEngine:
    """One engine, one credential. The retention job holds a second one whose role can delete
    and cannot write, so which URL an engine was built from is a meaningful thing to see at
    the call site (ADR-033)."""
    return create_async_engine(
        url,
        pool_pre_ping=True,
        pool_size=5,
        max_overflow=5,
        pool_recycle=1800,
        echo=False,  # never echo SQL; it would log untrusted values
    )


async def ping(engine: AsyncEngine) -> bool:
    """Return True when a trivial round trip succeeds. Exceptions propagate to the caller."""
    async with engine.connect() as connection:
        result = await connection.execute(text("SELECT 1"))
        # scalar_one() is untyped, so the comparison must be narrowed explicitly.
        return bool(result.scalar_one() == 1)


async def dispose(engine: AsyncEngine) -> None:
    await engine.dispose()
