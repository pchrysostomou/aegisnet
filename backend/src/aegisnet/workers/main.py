"""Worker process entrypoint: ``dramatiq aegisnet.workers.main``.

Importing this module boots the worker: it configures logging, installs the
authenticated Redis broker as the process-wide default, and only then imports the actor
module so every actor binds to that broker. Nothing else imports this module.

Actors registered: ``import_dataset`` (Chunk 4). The scheduler and periodic sweeps stay
deferred to Milestone 2 (ADR-010).
"""

from __future__ import annotations

from aegisnet.adapters.queue.broker import install
from aegisnet.config import get_settings
from aegisnet.logging import configure_logging, get_logger

logger = get_logger(__name__)

_settings = get_settings()
configure_logging(level=_settings.log_level, secrets=_settings.secret_values())
broker = install(_settings)

from aegisnet.adapters.queue.names import INGEST_QUEUE  # noqa: E402
from aegisnet.workers import actors  # noqa: E402,F401 - must follow install() so actors bind to it

logger.info(
    "worker_started",
    extra={"actors_registered": sorted(broker.actors), "queue": INGEST_QUEUE},
)
