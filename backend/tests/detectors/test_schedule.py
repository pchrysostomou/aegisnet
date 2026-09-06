"""ADR-020: the scheduled sweep's arithmetic, the post-ingest intervals, the periodic
actors' registration, and the broker carrying the periodiq middleware."""

from __future__ import annotations

import importlib
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from itertools import pairwise
from uuid import UUID

import dramatiq
import pytest
from dramatiq.brokers.stub import StubBroker
from periodiq import PeriodiqMiddleware

from aegisnet.adapters.queue import broker as broker_module
from aegisnet.adapters.queue.names import (
    DETECTION_QUEUE,
    NIGHTLY_BASELINES_ACTOR,
    NIGHTLY_RETENTION_ACTOR,
    SCHEDULED_SWEEP_ACTOR,
)
from aegisnet.services.detection_service import SweepError
from aegisnet.services.schedule import (
    baseline_cron,
    post_ingest_intervals,
    scheduled_interval,
    sweep_batch,
    sweep_cron,
)
from tests.conftest import make_settings
from tests.detectors.conftest import flow_row
from tests.fakes import FakeEventStore

pytestmark = pytest.mark.unit

T = datetime(2026, 9, 5, 12, 34, 56, tzinfo=UTC)


def test_cron_lines_follow_the_settings() -> None:
    assert sweep_cron(10) == "*/10 * * * *"
    assert sweep_cron(1) == "* * * * *"
    assert sweep_cron(60) == "*/60 * * * *"
    assert baseline_cron(2) == "0 2 * * *"
    with pytest.raises(ValueError, match="divide 60"):
        sweep_cron(7)
    with pytest.raises(ValueError, match=r"0\.\.23"):
        baseline_cron(24)


def test_scheduled_interval_ends_on_the_cadence_grid_and_looks_back() -> None:
    start, end = scheduled_interval(T, cadence_minutes=10, lookback_minutes=60)
    assert end == datetime(2026, 9, 5, 12, 30, tzinfo=UTC)
    assert start == datetime(2026, 9, 5, 11, 30, tzinfo=UTC)
    # Two ticks a few seconds apart sweep the same interval; dedup makes the overlap free.
    assert scheduled_interval(
        T + timedelta(seconds=40), cadence_minutes=10, lookback_minutes=60
    ) == (
        start,
        end,
    )


def test_scheduled_interval_refuses_a_naive_clock() -> None:
    with pytest.raises(SweepError):
        scheduled_interval(T.replace(tzinfo=None), cadence_minutes=10, lookback_minutes=60)


def test_post_ingest_intervals_are_hour_aligned_and_cover_the_last_event() -> None:
    first = datetime(2026, 9, 1, 0, 0, 4, tzinfo=UTC)
    last = datetime(2026, 9, 1, 1, 35, 20, tzinfo=UTC)
    assert post_ingest_intervals(first, last) == [
        (datetime(2026, 9, 1, 0, tzinfo=UTC), datetime(2026, 9, 1, 2, tzinfo=UTC))
    ]
    on_the_hour = datetime(2026, 9, 1, 13, 0, tzinfo=UTC)
    [(start, end)] = post_ingest_intervals(on_the_hour, on_the_hour)
    assert start == on_the_hour and end == on_the_hour + timedelta(hours=1)


def test_post_ingest_intervals_split_at_the_sweep_maximum() -> None:
    first = datetime(2026, 9, 1, 5, 0, tzinfo=UTC)
    intervals = post_ingest_intervals(first, first + timedelta(days=2, hours=3))
    assert [end - start for start, end in intervals] == [
        timedelta(days=1),
        timedelta(days=1),
        timedelta(hours=4),
    ]
    assert intervals[0][0] == first and intervals[-1][1] == first + timedelta(days=2, hours=4)
    for (_, end), (start, _) in pairwise(intervals):
        assert end == start
    with pytest.raises(ValueError, match="precedes"):
        post_ingest_intervals(first, first - timedelta(seconds=1))


async def test_sweep_batch_queues_one_interval_per_hour_block_and_nothing_for_an_empty_batch() -> (
    None
):
    store = FakeEventStore()
    batch = UUID(int=7)
    for minute in (5, 20, 59):
        row = flow_row(datetime(2026, 9, 1, 10, minute, tzinfo=UTC), "10.0.0.1", "10.0.0.2", 80)
        store.rows[row.id] = replace(row, batch_id=batch)
    queued: list[tuple[datetime, datetime]] = []

    async def enqueue(start: datetime, end: datetime) -> str:
        queued.append((start, end))
        return "m"

    intervals = await sweep_batch(store, batch, enqueue)
    assert (
        intervals
        == queued
        == [(datetime(2026, 9, 1, 10, tzinfo=UTC), datetime(2026, 9, 1, 11, tzinfo=UTC))]
    )
    assert await sweep_batch(store, UUID(int=8), enqueue) == []
    assert len(queued) == 1


def test_the_broker_carries_the_periodiq_middleware_with_the_configured_skip_delay() -> None:
    broker = broker_module.build_broker(make_settings(schedule_skip_delay_seconds=120))
    [middleware] = [m for m in broker.middleware if isinstance(m, PeriodiqMiddleware)]
    assert middleware.skip_delay == 120
    assert "periodic" in broker.actor_options


def test_the_periodic_actors_register_with_their_cron_lines(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``periodiq aegisnet.workers.main`` reads the ``periodic`` option of every declared
    actor; both must be on the detection queue so the worker runs them."""
    monkeypatch.setenv("SWEEP_CADENCE_MINUTES", "15")
    monkeypatch.setenv("BASELINE_RECOMPUTE_HOUR", "3")
    from aegisnet.config import get_settings

    get_settings.cache_clear()
    previous = dramatiq.get_broker()
    stub = StubBroker()
    stub.add_middleware(PeriodiqMiddleware())
    dramatiq.set_broker(stub)
    try:
        from aegisnet.workers import schedule

        if SCHEDULED_SWEEP_ACTOR not in stub.get_declared_actors():
            schedule = importlib.reload(schedule)  # re-run the decorators against the stub
        declared = stub.get_declared_actors()
        # All three. `nightly_retention` (Chunk 25, ADR-033) went unasserted here for eight
        # chunks, so the scheduler could have stopped sending it with the suite still green.
        assert {
            SCHEDULED_SWEEP_ACTOR,
            NIGHTLY_BASELINES_ACTOR,
            NIGHTLY_RETENTION_ACTOR,
        } <= declared
        sweep = stub.get_actor(SCHEDULED_SWEEP_ACTOR)
        nightly = stub.get_actor(NIGHTLY_BASELINES_ACTOR)
        retention = stub.get_actor(NIGHTLY_RETENTION_ACTOR)
        assert sweep.queue_name == nightly.queue_name == retention.queue_name == DETECTION_QUEUE
        assert schedule.SWEEP_CRON == "*/15 * * * *" and schedule.BASELINE_CRON == "0 3 * * *"
        assert schedule.RETENTION_CRON == "0 3 * * *"
        assert str(sweep.options["periodic"]) == "*/15 * * * *"
        assert str(nightly.options["periodic"]) == "0 3 * * *"
        assert str(retention.options["periodic"]) == "0 3 * * *"
        assert sweep.options["max_retries"] == 0 and nightly.options["max_retries"] == 0
        # The prune is the one job where a retry could delete twice as much as intended.
        assert retention.options["max_retries"] == 0
    finally:
        dramatiq.set_broker(previous)
        get_settings.cache_clear()
