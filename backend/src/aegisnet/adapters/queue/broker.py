"""Dramatiq broker configuration.

**No actors are registered here.** The worker container runs this module so that the
topology, image, and broker connection are proven early, but it has no business workload
until the EVE normalisation actor lands in Chunk 4. Its container healthcheck is
process-level liveness only and asserts nothing about capability (ADR-010).

Deliberately absent: any placeholder actor, heartbeat job, or synthetic task created
merely to make the worker look busy.
"""

from __future__ import annotations

import dramatiq
from dramatiq.brokers.redis import RedisBroker

from aegisnet.config import Settings, get_settings
from aegisnet.logging import configure_logging, get_logger

logger = get_logger(__name__)


def build_broker(settings: Settings) -> RedisBroker:
    # Dramatiq ships no annotations for RedisBroker.__init__, so the call is untyped.
    # The ignore is narrow and deliberate rather than a project-wide mypy relaxation.
    return RedisBroker(  # type: ignore[no-untyped-call]
        url=settings.redis_url,
        password=settings.redis_password.get_secret_value(),
    )


def install(settings: Settings | None = None) -> RedisBroker:
    """Create the broker and register it as the process-wide default."""
    resolved = settings or get_settings()
    broker = build_broker(resolved)
    dramatiq.set_broker(broker)
    return broker


# Importing this module is how `dramatiq aegisnet.adapters.queue.broker` boots.
_settings = get_settings()
configure_logging(level=_settings.log_level, secrets=_settings.secret_values())
broker = install(_settings)
logger.info("worker_started", extra={"actors_registered": 0, "workload": "none_until_chunk_4"})
