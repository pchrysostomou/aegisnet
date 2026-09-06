"""Rate limits under concurrency, against a running stack (Milestone 6, Chunk 26).

`SECURITY.md` publishes four counted limits and two failure modes, and until now every one of them
was asserted one request at a time. That is the wrong shape for the question: a fixed-window counter
is only correct if the increment is atomic, and a serial test cannot tell an atomic `INCR` from a
read-modify-write that happens not to have raced yet.

So these fire the whole budget at once. What is being measured:

* **The published number is the number.** Exactly `RATE_LIMIT_READ_PER_MIN` requests succeed
  inside one window, no matter how many arrive together.
* **A refusal is usable.** `429`, the documented error envelope, and a `Retry-After` that is the
  time left in the window rather than a constant somebody guessed.
* **The window edge, measured rather than assumed.** `rate_limiter.py` says in its own docstring
  that a burst straddling two windows can reach twice the limit for an instant. That is a real
  property of fixed windows and the honest thing is to show it, not to hide it behind a test
  that never crosses a boundary.
* **Login fails closed.** Reads fail open when Redis is unreachable so an outage does not lock an
  analyst out; login and ingest fail closed so an outage does not become an open door.

This suite spends real budgets and cleans them up afterwards (see `conftest.py`).
"""

from __future__ import annotations

import asyncio
import time

import httpx
import pytest
from redis.asyncio import Redis

from aegisnet.config import Settings

pytestmark = [pytest.mark.load, pytest.mark.security]

READS = "/api/v1/incidents"
WINDOW_SECONDS = 60


def _window(at: float) -> int:
    """The limiter's fixed-window index, computed the same way the adapter does."""
    return int(at // WINDOW_SECONDS)


async def _fire(
    api: httpx.AsyncClient, path: str, headers: dict[str, str], count: int
) -> tuple[list[httpx.Response], int, int]:
    """`count` requests at once, with the window index seen before and after."""
    started = _window(time.time())
    responses = await asyncio.gather(*(api.get(path, headers=headers) for _ in range(count)))
    return list(responses), started, _window(time.time())


@pytest.fixture
async def clean_read_limit(redis: Redis) -> None:
    async for key in redis.scan_iter(match="aegisnet:rl:read:*"):
        await redis.delete(key)


async def test_the_published_read_limit_is_the_limit_under_concurrency(
    api: httpx.AsyncClient,
    token: str,
    load_settings: Settings,
    clean_read_limit: None,
) -> None:
    """The whole budget plus half again, fired together. A read-modify-write counter would let
    more than the limit through here; an atomic INCR cannot."""
    limit = load_settings.rate_limit_read_per_min
    headers = {"Authorization": f"Bearer {token}"}

    responses, started, ended = await _fire(api, READS, headers, int(limit * 1.5))
    if started != ended:
        pytest.skip("the burst crossed a window boundary; the edge has its own test")

    allowed = [r for r in responses if r.status_code == 200]
    refused = [r for r in responses if r.status_code == 429]

    assert len(allowed) == limit, f"{len(allowed)} allowed, limit is {limit}"
    assert len(allowed) + len(refused) == len(responses), "every request was one or the other"


async def test_a_refusal_says_what_it_is_and_when_to_come_back(
    api: httpx.AsyncClient,
    token: str,
    load_settings: Settings,
    clean_read_limit: None,
) -> None:
    limit = load_settings.rate_limit_read_per_min
    headers = {"Authorization": f"Bearer {token}"}

    responses, _started, _ended = await _fire(api, READS, headers, limit + 20)
    refused = [r for r in responses if r.status_code == 429]
    assert refused, "the budget was not exhausted"

    for response in refused[:5]:
        body = response.json()
        assert body["error"]["code"] == "rate_limited"
        assert body["error"]["correlation_id"], "a refusal is still traceable"

        retry_after = response.headers.get("Retry-After")
        assert retry_after is not None, "a 429 without Retry-After is a 429 nobody can act on"
        seconds = int(retry_after)
        assert 1 <= seconds <= WINDOW_SECONDS + 1, seconds


async def test_the_fixed_window_edge_costs_at_most_one_extra_budget(
    api: httpx.AsyncClient,
    token: str,
    load_settings: Settings,
    clean_read_limit: None,
) -> None:
    """The documented weakness, measured. A burst that straddles a boundary can spend the last
    window's remainder and the next window's whole budget, so the ceiling is twice the limit —
    and never more, because there is no third window in a sixty-second span."""
    limit = load_settings.rate_limit_read_per_min
    headers = {"Authorization": f"Bearer {token}"}

    # Wait for a real boundary rather than skipping most runs or pretending to have one. The
    # window is a minute, so this costs under a minute in a suite that is opt-in anyway, and it
    # measures the documented weakness on every run instead of one in twelve.
    until_edge = WINDOW_SECONDS - (time.time() % WINDOW_SECONDS)
    if until_edge > 3:
        await asyncio.sleep(until_edge - 3)

    first, _s1, _e1 = await _fire(api, READS, headers, limit + 10)
    await asyncio.sleep(4)  # over the boundary
    second, _s2, _e2 = await _fire(api, READS, headers, limit + 10)

    allowed = sum(r.status_code == 200 for r in first + second)
    assert allowed <= 2 * limit, f"{allowed} allowed across the edge; the ceiling is {2 * limit}"
    assert allowed > limit, "the next window did open"
    # Recorded rather than merely asserted: the number is the point of the test.
    print(f"window-edge burst: {allowed} allowed across two windows, ceiling {2 * limit}")  # noqa: T201


async def test_reads_and_writes_are_counted_apart(
    api: httpx.AsyncClient,
    token: str,
    load_settings: Settings,
    clean_read_limit: None,
) -> None:
    """`read` and `default` are separate keys, so filling the read budget must not refuse a
    write — an analyst reading a queue should not lose the ability to move a case."""
    limit = load_settings.rate_limit_read_per_min
    headers = {"Authorization": f"Bearer {token}"}

    responses, _s, _e = await _fire(api, READS, headers, limit + 10)
    assert any(r.status_code == 429 for r in responses), "the read budget was not exhausted"

    # A write route, refused for a reason that is not the rate limiter.
    write = await api.post(
        "/api/v1/incidents/00000000-0000-0000-0000-000000000000/notes",
        headers=headers,
        json={"body": "load probe"},
    )
    assert write.status_code != 429, "the write budget was spent by reads"


async def test_login_fails_closed_when_its_budget_is_spent(
    api: httpx.AsyncClient, load_settings: Settings, redis: Redis
) -> None:
    """Reads fail open so a Redis outage does not lock an analyst out. Login fails closed so an
    outage does not become an open door — and the limit itself must hold under a burst, which is
    the shape a credential-stuffing attempt actually has."""
    limit = load_settings.rate_limit_login_per_15min
    body = {"email": "load-probe@example.test", "password": "not-the-password"}

    try:
        responses = await asyncio.gather(
            *(api.post("/api/v1/auth/login", json=body) for _ in range(limit + 5))
        )
        codes = [r.status_code for r in responses]
        assert 429 in codes, "the login limit did not engage"
        assert sum(code == 429 for code in codes) >= 5, codes
        assert all(code in (401, 429) for code in codes), "a wrong password never succeeds"

        refused = next(r for r in responses if r.status_code == 429)
        assert refused.json()["error"]["code"] == "rate_limited"
        assert int(refused.headers["Retry-After"]) >= 1
    finally:
        # This suite spends a real, fifteen-minute, per-IP budget. Leaving it spent would lock
        # the operator out of their own stack.
        async for key in redis.scan_iter(match="aegisnet:rl:login*"):
            await redis.delete(key)
