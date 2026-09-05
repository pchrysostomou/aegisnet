"""Build and version metadata.

``GIT_SHA`` is injected as a build argument by CI and by ``docker compose build``.
It is intentionally reported only outside production (see api/v1/meta.py).

``schema_revision()`` is the Alembic head found in the migration scripts shipped with this
build: the revision the code *expects*, not necessarily the one the database *has*. The two
are compared by ``make migrate-status``; a readiness check on the difference is deferred.
"""

from __future__ import annotations

import os
from functools import lru_cache

from aegisnet import __version__

APP_VERSION: str = __version__


def git_sha() -> str:
    return os.environ.get("GIT_SHA", "unknown")


@lru_cache(maxsize=1)
def schema_revision() -> str | None:
    """Head revision of the packaged migration scripts, or ``None`` if there are none."""
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    from aegisnet.adapters.db.migrations import MIGRATIONS_DIR

    config = Config()
    config.set_main_option("script_location", str(MIGRATIONS_DIR))
    return ScriptDirectory.from_config(config).get_current_head()
