"""The Redis rate limiter and denylist against fakeredis: windows, costs, TTLs."""

from __future__ import annotations

from collections.abc import AsyncIterator

import fakeredis
import pytest

from aegisnet.adapters.cache.rate_limiter import PREFIX, RedisRateLimiter, RedisTokenDenylist

pytestmark = pytest.mark.unit


class Ticker:
    def __init__(self, start: float = 1_000_000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now


@pytest.fixture
async def redis() -> AsyncIterator[fakeredis.FakeAsyncRedis]:
    client = fakeredis.FakeAsyncRedis()
    try:
        yield client
    finally:
        await client.aclose()


async def test_hits_count_down_to_the_limit_then_refuse_until_the_window_ends(
    redis: fakeredis.FakeAsyncRedis,
) -> None:
    ticker = Ticker()
    limiter = RedisRateLimiter(redis, clock=ticker)
    decisions = [
        await limiter.hit("login_ip", "10.0.0.1", limit=3, window_seconds=60) for _ in range(4)
    ]
    assert [d.allowed for d in decisions] == [True, True, True, False]
    assert [d.remaining for d in decisions] == [2, 1, 0, 0]
    assert decisions[0].retry_after == 0 and 1 <= decisions[3].retry_after <= 61
    key = f"{PREFIX}:rl:login_ip:10.0.0.1:{int(ticker.now // 60)}"
    assert 0 < await redis.ttl(key) <= 61
    ticker.now += 60
    assert (await limiter.hit("login_ip", "10.0.0.1", limit=3, window_seconds=60)).allowed


async def test_subjects_names_and_costs_are_independent(redis: fakeredis.FakeAsyncRedis) -> None:
    limiter = RedisRateLimiter(redis, clock=Ticker())
    hit = limiter.hit
    assert (await hit("ingest_bytes", "a", limit=100, window_seconds=3600, cost=90)).allowed
    assert not (await hit("ingest_bytes", "a", limit=100, window_seconds=3600, cost=20)).allowed
    assert (await hit("ingest_bytes", "b", limit=100, window_seconds=3600, cost=20)).allowed
    assert (await hit("ingest", "a", limit=100, window_seconds=3600, cost=20)).allowed


async def test_the_denylist_remembers_a_token_for_its_remaining_life(
    redis: fakeredis.FakeAsyncRedis,
) -> None:
    denylist = RedisTokenDenylist(redis)
    assert not await denylist.contains("jti-1")
    await denylist.add("jti-1", 900)
    assert await denylist.contains("jti-1")
    assert 0 < await redis.ttl(f"{PREFIX}:deny:jti-1") <= 900
    await denylist.add("jti-2", 0)
    assert await redis.ttl(f"{PREFIX}:deny:jti-2") == 1
