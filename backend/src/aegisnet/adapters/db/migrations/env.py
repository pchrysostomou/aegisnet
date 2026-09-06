"""Alembic environment.

Runs every revision through the async engine with the **migrator** credentials from the
settings object (``Settings.migration_url``). ``alembic.ini`` carries no URL, so no
credential can be committed by way of this environment.

Two ways in:

- The ``alembic`` CLI (``make migrate``): no connection is supplied, so this module opens
  one itself with ``asyncio.run``.
- Tests: ``config.attributes["connection"]`` holds an already-open synchronous connection
  (obtained via ``AsyncConnection.run_sync``), and the revision runs on it.

Role names are handed to revisions through ``config.attributes`` — ``app_role`` and, since
revision 0006, ``retention_role`` — so that the GRANT statements never hard-code one.
"""

from __future__ import annotations

import asyncio
from typing import Any

from alembic import context
from sqlalchemy import Connection
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

from aegisnet.adapters.db.models import Base
from aegisnet.config import get_settings
from aegisnet.logging import configure_logging

config = context.config
target_metadata = Base.metadata


def _configure_context(**kwargs: Any) -> None:
    context.configure(
        target_metadata=target_metadata,
        compare_type=True,
        compare_server_default=False,
        render_as_batch=False,
        **kwargs,
    )


def run_migrations_offline() -> None:
    """Emit SQL to stdout without connecting (``alembic upgrade head --sql``)."""
    settings = get_settings()
    config.attributes.setdefault("app_role", settings.postgres_app_user)
    config.attributes.setdefault("retention_role", settings.postgres_retention_user)
    _configure_context(
        url=settings.migration_url.render_as_string(hide_password=True),
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def _run_on_connection(connection: Connection) -> None:
    _configure_context(connection=connection)
    with context.begin_transaction():
        context.run_migrations()


async def _run_async() -> None:
    settings = get_settings()
    configure_logging(level=settings.log_level, secrets=settings.secret_values())
    config.attributes.setdefault("app_role", settings.postgres_app_user)
    config.attributes.setdefault("retention_role", settings.postgres_retention_user)
    engine = create_async_engine(settings.migration_url, poolclass=NullPool)
    try:
        async with engine.connect() as connection:
            await connection.run_sync(_run_on_connection)
    finally:
        await engine.dispose()


def run_migrations_online() -> None:
    connection = config.attributes.get("connection")
    if connection is not None:
        settings = get_settings()
        config.attributes.setdefault("app_role", settings.postgres_app_user)
        config.attributes.setdefault("retention_role", settings.postgres_retention_user)
        _run_on_connection(connection)
        return
    asyncio.run(_run_async())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
