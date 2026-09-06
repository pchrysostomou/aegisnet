"""Periodic actors (ADR-020), sent by ``periodiq aegisnet.workers.main`` and run by the
worker like any other message. The scheduler process only *sends*; if it is down, nothing
periodic happens and nothing else breaks. All three actors read their parameters from
settings at import time, which is when periodiq reads the cron lines too.

The retention actor is sent nightly regardless of `RETENTION_ENABLED`; the actor itself is
where the setting is read, so enabling the policy needs no change here (ADR-033).
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import dramatiq
from periodiq import cron

from aegisnet.adapters.queue.names import (
    DETECTION_QUEUE,
    NIGHTLY_BASELINES_ACTOR,
    NIGHTLY_RETENTION_ACTOR,
    SCHEDULED_SWEEP_ACTOR,
)
from aegisnet.config import get_settings
from aegisnet.logging import get_logger
from aegisnet.services.schedule import baseline_cron, scheduled_interval, sweep_cron
from aegisnet.workers.actors import (
    IMPORT_TIME_LIMIT_MS,
    run_baselines,
    run_retention,
    run_sweep,
)

logger = get_logger(__name__)

_settings = get_settings()
SWEEP_CRON = sweep_cron(_settings.sweep_cadence_minutes)
BASELINE_CRON = baseline_cron(_settings.baseline_recompute_hour)
RETENTION_CRON = baseline_cron(_settings.retention_hour)


@dramatiq.actor(
    actor_name=SCHEDULED_SWEEP_ACTOR,
    queue_name=DETECTION_QUEUE,
    periodic=cron(SWEEP_CRON),
    max_retries=0,
    time_limit=IMPORT_TIME_LIMIT_MS,
)
def scheduled_sweep() -> None:
    settings = get_settings()
    start, end = scheduled_interval(
        datetime.now(UTC),
        cadence_minutes=settings.sweep_cadence_minutes,
        lookback_minutes=settings.sweep_lookback_minutes,
    )
    logger.info(
        "scheduled_sweep", extra={"window_start": start.isoformat(), "window_end": end.isoformat()}
    )
    asyncio.run(run_sweep(start, end))


@dramatiq.actor(
    actor_name=NIGHTLY_BASELINES_ACTOR,
    queue_name=DETECTION_QUEUE,
    periodic=cron(BASELINE_CRON),
    max_retries=0,
    time_limit=IMPORT_TIME_LIMIT_MS,
)
def nightly_baselines() -> None:
    window_days = get_settings().baseline_window_days
    logger.info("nightly_baselines", extra={"window_days": window_days})
    asyncio.run(run_baselines(window_days))


@dramatiq.actor(
    actor_name=NIGHTLY_RETENTION_ACTOR,
    queue_name=DETECTION_QUEUE,
    periodic=cron(RETENTION_CRON),
    max_retries=0,
    time_limit=IMPORT_TIME_LIMIT_MS,
)
def nightly_retention() -> None:
    """Apply the retention policy, if it is turned on.

    The message is sent every night whether or not the policy is enabled, and `run_retention`
    decides — so turning it on is one setting and a worker restart, and the scheduler holds no
    opinion about it. `max_retries=0` because a prune that failed halfway has already committed
    whole batches and the next night resumes from there; rows do not get younger.
    """
    logger.info("nightly_retention")
    asyncio.run(run_retention())
