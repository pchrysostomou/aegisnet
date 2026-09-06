"""Pure domain layer.

Nothing here may import from ``aegisnet.adapters``, ``aegisnet.services`` or ``aegisnet.api``
(ARCHITECTURE §1). mypy runs in strict mode on this package (``pyproject.toml``).

The schema enumerations live here because both the ORM models (an adapter) and the EVE
normaliser (domain) need them, and the dependency may only point one way.
"""
