"""Pure domain layer.

Nothing here may import from ``aegisnet.adapters``, ``aegisnet.services`` or ``aegisnet.api``
(ARCHITECTURE §1). mypy runs in strict mode on this package (``pyproject.toml``).

Chunk 2 places only the schema enumerations here, because the ORM models (an adapter) and
the EVE normaliser that arrives in Chunk 3 (domain) both need them, and the dependency may
only point one way.
"""
