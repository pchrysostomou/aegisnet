"""The daily cap on outbound briefs (T-3.4; ADR-030, ADR-031).

A budget that lives in one process is not a budget. The API, the worker and the CLI each build
their own client, so an in-memory counter caps each of them separately — an operator who sets
50 gets 150 — and it resets on every restart, which is the moment a runaway loop is most likely
to have just happened.

So the number lives in Redis, keyed by UTC day, incremented atomically, and expiring on its own
two days later. It is the same fixed-window shape as the rate limiter and it is deliberate:
cheap, correct under concurrency, and with one honest edge — a burst straddling midnight can
spend one day's last call and the next day's first at the same instant.

Nothing here is touched when the feature is off or unconfigured: the client refuses on those
before it reaches the budget, so a deployment with no key never opens a connection to count
calls it will not make.

`InMemoryDailyBudget` is what the tests use and what a client falls back to when it is handed
no Redis. It is honest about being per-process.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, date, datetime
from typing import Final, Protocol

from redis.asyncio import Redis

from aegisnet.adapters.perplexity.errors import BriefUnavailableError

PREFIX: Final = "aegisnet:brief:budget"
KEEP_SECONDS: Final = 2 * 24 * 60 * 60
"""Two days, so yesterday's count is still readable while today's is being spent."""


def _utc_today(clock: Callable[[], datetime]) -> date:
    return clock().astimezone(UTC).date()


def _refuse(limit: int) -> BriefUnavailableError:
    return BriefUnavailableError("budget_exhausted", f"the daily brief budget of {limit} is spent")


class BriefBudget(Protocol):
    """A hard stop, asked once per call that is about to leave."""

    async def take(self) -> None: ...


class InMemoryDailyBudget:
    """Per-process, per-UTC-day. Correct for one process and no use across three."""

    def __init__(
        self, limit: int, *, clock: Callable[[], datetime] = lambda: datetime.now(UTC)
    ) -> None:
        self._limit = limit
        self._clock = clock
        self._day: date | None = None
        self._used = 0

    @property
    def used(self) -> int:
        self._roll()
        return self._used

    def _roll(self) -> None:
        today = _utc_today(self._clock)
        if self._day != today:
            self._day, self._used = today, 0

    async def take(self) -> None:
        self._roll()
        if self._used >= self._limit:
            raise _refuse(self._limit)
        self._used += 1


class RedisDailyBudget:
    """Shared by every process pointed at the same Redis.

    The counter is incremented before the call rather than after it, so a call that is made and
    then fails still costs its slot. Charging only for successes would let a broken endpoint be
    retried without limit, which is the failure this cap exists to bound.

    A refused attempt also increments. That is deliberate: it costs nothing, and it keeps the
    counter a record of how hard something tried rather than of how much it achieved.
    """

    def __init__(
        self,
        client: Redis,
        limit: int,
        *,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._client = client
        self._limit = limit
        self._clock = clock

    async def take(self) -> None:
        key = f"{PREFIX}:{_utc_today(self._clock).isoformat()}"
        used = int(await self._client.incr(key))
        if used == 1:
            await self._client.expire(key, KEEP_SECONDS)
        if used > self._limit:
            raise _refuse(self._limit)

    async def used(self) -> int:
        key = f"{PREFIX}:{_utc_today(self._clock).isoformat()}"
        return int(await self._client.get(key) or 0)


__all__ = [
    "KEEP_SECONDS",
    "PREFIX",
    "BriefBudget",
    "InMemoryDailyBudget",
    "RedisDailyBudget",
]
