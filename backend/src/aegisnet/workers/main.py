"""Process entrypoint for both the worker (``dramatiq aegisnet.workers.main``) and the
scheduler (``periodiq aegisnet.workers.main``).

Importing this module boots the process: it configures logging, installs the
authenticated Redis broker as the process-wide default, and only then imports the actor
modules so every actor binds to that broker. Nothing else imports this module.

Actors registered: the ingest imports, the detection sweep and the baseline recompute
(``actors``), plus the two periodic ones the scheduler sends (``schedule``, ADR-020).
"""

from __future__ import annotations

from aegisnet.adapters.queue.broker import install
from aegisnet.config import get_settings
from aegisnet.logging import configure_logging, get_logger

logger = get_logger(__name__)

_settings = get_settings()
configure_logging(level=_settings.log_level, secrets=_settings.secret_values())
broker = install(_settings)

from aegisnet.adapters.queue.names import DETECTION_QUEUE, INGEST_QUEUE  # noqa: E402
from aegisnet.workers import (  # noqa: E402,F401 - must follow install() so actors bind to it
    actors,
    schedule,
)

logger.info(
    "worker_started",
    extra={
        "actors_registered": sorted(broker.actors),
        "queues": [INGEST_QUEUE, DETECTION_QUEUE],
        "sweep_cron": schedule.SWEEP_CRON,
        "baseline_cron": schedule.BASELINE_CRON,
    },
)
