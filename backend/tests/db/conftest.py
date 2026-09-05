"""Fixtures for the database suite.

Opt-in only. The suite runs when ``AEGISNET_DB_TESTS=1`` and the ``POSTGRES_*`` variables
point at an ephemeral PostgreSQL whose roles were created by
``infra/postgres/init/01_roles.sh`` — which is exactly what ``make test-db`` provides via
``docker-compose.test.yml --profile db``. Otherwise every test marked ``db`` is skipped and
the default suite stays hermetic.

Migrations are applied once per session through Alembic's command API, which runs
``env.py`` and therefore opens its own connection with the migrator credentials; that
happens in a synchronous fixture so ``asyncio.run`` inside ``env.py`` has no running loop
to collide with. The tests themselves are async and use short-lived engines.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator, Iterator

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine
from sqlalchemy.pool import NullPool

from aegisnet.adapters.db.migrations import MIGRATIONS_DIR
from aegisnet.config import Settings
from tests.conftest import make_settings

DB_FLAG = "AEGISNET_DB_TESTS"


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if os.environ.get(DB_FLAG) == "1":
        return
    skip = pytest.mark.skip(
        reason=f"database suite: set {DB_FLAG}=1 with POSTGRES_* pointing at an ephemeral "
        "PostgreSQL (make test-db)"
    )
    for item in items:
        if "db" in item.keywords:
            item.add_marker(skip)


def alembic_config(settings: Settings) -> Config:
    """Programmatic equivalent of ``alembic.ini``; no URL, env.py reads the settings."""
    config = Config()
    config.set_main_option("script_location", str(MIGRATIONS_DIR))
    config.attributes["app_role"] = settings.postgres_app_user
    return config


@pytest.fixture(scope="session")
def db_settings() -> Settings:
    # make_settings() reads the process environment (POSTGRES_HOST etc.) but never a .env
    # file, so the suite is driven entirely by the compose service definition.
    return make_settings()


@pytest.fixture(scope="session")
def migrated(db_settings: Settings) -> Iterator[Config]:
    """The schema at head for the whole session, torn down to base afterwards."""
    config = alembic_config(db_settings)
    command.upgrade(config, "head")
    yield config
    command.downgrade(config, "base")


@pytest.fixture
async def migrator_engine(db_settings: Settings, migrated: Config) -> AsyncIterator[AsyncEngine]:
    engine = create_async_engine(db_settings.migration_url, poolclass=NullPool)
    try:
        yield engine
    finally:
        await engine.dispose()


@pytest.fixture
async def app_engine(db_settings: Settings, migrated: Config) -> AsyncIterator[AsyncEngine]:
    """Connects as the runtime role, the one whose privileges T-5.3 constrains."""
    engine = create_async_engine(db_settings.database_url, poolclass=NullPool)
    try:
        yield engine
    finally:
        await engine.dispose()
