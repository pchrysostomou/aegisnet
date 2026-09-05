"""Redis-backed rate limiting and access-token denylist (FR-10.4, T-2.4).

Fixed windows: one counter per (name, subject, window index), incremented atomically and
given the window's TTL on first use. Simple, cheap, and honest about its edge: a burst
straddling two windows can reach twice the limit for an instant. ``retry_after`` is the
time left in the current window.

Both classes take the async client the application already holds in ``app.state.redis``.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Final

from redis.asyncio import Redis

from aegisnet.domain.ports import RateLimitDecision

PREFIX: Final = "aegisnet"


class RedisRateLimiter:
    def __init__(self, client: Redis, *, clock: Callable[[], float] = time.time) -> None:
        self._client = client
        self._clock = clock

    async def hit(
        self, name: str, subject: str, *, limit: int, window_seconds: int, cost: int = 1
    ) -> RateLimitDecision:
        now = self._clock()
        index = int(now // window_seconds)
        key = f"{PREFIX}:rl:{name}:{subject}:{index}"
        count = int(await self._client.incrby(key, cost))
        if count == cost:
            await self._client.expire(key, window_seconds + 1)
        window_end = (index + 1) * window_seconds
        retry_after = max(1, int(window_end - now) + 1)
        return RateLimitDecision(
            allowed=count <= limit,
            remaining=max(limit - count, 0),
            retry_after=retry_after if count > limit else 0,
        )


class RedisTokenDenylist:
    def __init__(self, client: Redis) -> None:
        self._client = client

    async def add(self, token_id: str, ttl_seconds: int) -> None:
        await self._client.set(f"{PREFIX}:deny:{token_id}", "1", ex=max(1, ttl_seconds))

    async def contains(self, token_id: str) -> bool:
        return bool(await self._client.exists(f"{PREFIX}:deny:{token_id}"))
