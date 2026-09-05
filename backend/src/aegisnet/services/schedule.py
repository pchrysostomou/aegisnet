"""When sweeps run without an operator asking (ADR-020).

Two triggers feed the ``detection`` queue besides ``POST /detections/sweeps``:

* the **scheduled sweep**: every ``SWEEP_CADENCE_MINUTES`` the scheduler fires an actor
  that sweeps the last ``SWEEP_LOOKBACK_MINUTES`` ending on the cadence grid. Consecutive
  ticks overlap on purpose, so an event that arrives late still meets a sweep; the alert
  dedup key turns the overlap into a no-op rather than a duplicate;
* the **post-ingest sweep**: when a batch completes, the hour-aligned span of the events
  it stored is swept, split into intervals a single sweep accepts.

Everything here is arithmetic on aware instants; the actors and the route call it.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import datetime, timedelta
from typing import Protocol
from uuid import UUID

from aegisnet.domain.detectors import MAX_WINDOW, window_bucket
from aegisnet.services.detection_service import SweepError, validate_interval

HOUR_SECONDS = 3600


class SpanSource(Protocol):
    """Whoever can answer a batch's event-time span: the read store or the detection
    service in front of it."""

    async def batch_span(self, batch_id: UUID) -> tuple[datetime, datetime] | None: ...


def sweep_cron(cadence_minutes: int) -> str:
    """The five-field cron line for a tick every ``cadence_minutes`` on the hour grid."""
    if cadence_minutes < 1 or 60 % cadence_minutes:
        raise ValueError("the sweep cadence must divide 60 minutes")
    return "* * * * *" if cadence_minutes == 1 else f"*/{cadence_minutes} * * * *"


def baseline_cron(hour: int) -> str:
    """Once a day at ``hour`` on the scheduler's clock."""
    if not 0 <= hour <= 23:
        raise ValueError("the recompute hour must be 0..23")
    return f"0 {hour} * * *"


def scheduled_interval(
    now: datetime, *, cadence_minutes: int, lookback_minutes: int
) -> tuple[datetime, datetime]:
    """``[end - lookback, end)`` where ``end`` is ``now`` floored to the cadence grid, so
    two ticks that fire a few seconds apart sweep the same interval."""
    if now.tzinfo is None:
        raise SweepError("the scheduler's clock must be timezone-aware")
    end = window_bucket(now, cadence_minutes * 60)
    start = end - timedelta(minutes=lookback_minutes)
    validate_interval(start, end)
    return start, end


def post_ingest_intervals(first: datetime, last: datetime) -> list[tuple[datetime, datetime]]:
    """Hour-aligned intervals covering every event time in ``[first, last]``, each no longer
    than one sweep accepts. The end is the hour *after* ``last`` so an event sitting on the
    hour is inside a half-open interval."""
    if last < first:
        raise ValueError("the span's last instant precedes its first")
    start = window_bucket(first, HOUR_SECONDS)
    end = window_bucket(last, HOUR_SECONDS) + timedelta(seconds=HOUR_SECONDS)
    out: list[tuple[datetime, datetime]] = []
    cursor = start
    while cursor < end:
        stop = min(cursor + MAX_WINDOW, end)
        out.append((cursor, stop))
        cursor = stop
    return out


async def sweep_batch(
    events: SpanSource,
    batch_id: UUID,
    enqueue: Callable[[datetime, datetime], Awaitable[str]],
) -> list[tuple[datetime, datetime]]:
    """Queue the post-ingest sweeps for ``batch_id``; returns what was queued (nothing when
    the batch stored no events)."""
    span = await events.batch_span(batch_id)
    if span is None:
        return []
    intervals = post_ingest_intervals(*span)
    for start, end in intervals:
        await enqueue(start, end)
    return intervals
