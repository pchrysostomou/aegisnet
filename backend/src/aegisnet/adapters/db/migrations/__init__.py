"""Alembic migration environment, shipped inside the package (ADR-012).

``MIGRATIONS_DIR`` is the ``script_location``; ``alembic.ini`` at the backend root points
here for CLI use, and :func:`aegisnet.version.schema_revision` reads the head from here so
the API can report the schema revision its build expects.
"""

from __future__ import annotations

from pathlib import Path

MIGRATIONS_DIR: Path = Path(__file__).resolve().parent
