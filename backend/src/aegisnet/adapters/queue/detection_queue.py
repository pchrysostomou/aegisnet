"""Enqueue detection sweeps by actor name. A message carries the interval as two ISO 8601
instants, nothing else (TB-5)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

import dramatiq

from aegisnet.adapters.queue.names import (
    DETECTION_QUEUE,
    RECOMPUTE_BASELINES_ACTOR,
    RUN_DETECTORS_ACTOR,
)


class RedisDetectionQueue:
    def __init__(self, broker: dramatiq.Broker) -> None:
        self._broker = broker

    def enqueue_sweep(self, start: datetime, end: datetime) -> str:
        """Queue ``run_detectors`` over ``[start, end)``; returns the message id."""
        message: Any = dramatiq.Message(
            queue_name=DETECTION_QUEUE,
            actor_name=RUN_DETECTORS_ACTOR,
            args=(start.isoformat(), end.isoformat()),
            kwargs={},
            options={},
        )
        stored = self._broker.enqueue(message)  # type: ignore[no-untyped-call]
        return str(stored.message_id)

    def enqueue_baselines(self, window_days: int) -> str:
        """Queue ``recompute_baselines(window_days)``; returns the message id."""
        message: Any = dramatiq.Message(
            queue_name=DETECTION_QUEUE,
            actor_name=RECOMPUTE_BASELINES_ACTOR,
            args=(int(window_days),),
            kwargs={},
            options={},
        )
        stored = self._broker.enqueue(message)  # type: ignore[no-untyped-call]
        return str(stored.message_id)
