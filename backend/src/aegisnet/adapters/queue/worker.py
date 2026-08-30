"""Worker process entrypoint.

Importing this module is how ``dramatiq aegisnet.adapters.queue.worker`` boots: it
configures logging and installs the broker as the process-wide default. It is kept
separate from :mod:`aegisnet.adapters.queue.broker` so that the factory can be imported
by tests without triggering these side effects.

No actors are registered (ADR-010). The first real actor arrives in Chunk 4.
"""

from __future__ import annotations

from aegisnet.adapters.queue.broker import install
from aegisnet.config import get_settings
from aegisnet.logging import configure_logging, get_logger

logger = get_logger(__name__)

_settings = get_settings()
configure_logging(level=_settings.log_level, secrets=_settings.secret_values())
broker = install(_settings)
logger.info("worker_started", extra={"actors_registered": 0, "workload": "none_until_chunk_4"})
