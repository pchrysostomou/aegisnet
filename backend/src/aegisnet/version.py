"""Build and version metadata.

``GIT_SHA`` is injected as a build argument by CI and by ``docker compose build``.
It is intentionally reported only outside production (see api/v1/meta.py).
"""

from __future__ import annotations

import os

from aegisnet import __version__

APP_VERSION: str = __version__
SCHEMA_REVISION: str | None = None
"""Alembic head revision. ``None`` until migrations exist (Chunk 2)."""


def git_sha() -> str:
    return os.environ.get("GIT_SHA", "unknown")
