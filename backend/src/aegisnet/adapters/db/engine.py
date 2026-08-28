"""Thin async SQLAlchemy engine wiring.

Chunk 1 scope: create an engine and answer "can we reach PostgreSQL". No ORM models,
no sessions in request handlers, no migrations. Those arrive in Chunk 2.
"""

from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from aegisnet.config import Settings
from aegisnet.logging import get_logger

logger = get_logger(__name__)


def create_engine(settings: Settings) -> AsyncEngine:
    return create_async_engine(
        settings.database_url,
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
