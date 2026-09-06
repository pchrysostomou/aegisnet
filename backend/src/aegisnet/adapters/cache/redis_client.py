"""Thin async Redis client wiring.

This module is the client wiring only: create a client and answer "can we reach Redis".
The rate limiter and the token denylist live in ``rate_limiter``, and the brief cache is
content-addressed inside the Perplexity client.
"""

from __future__ import annotations

from redis.asyncio import Redis

from aegisnet.config import Settings


def create_client(settings: Settings) -> Redis:
    # ``from_url`` is annotated as returning Any, so bind it to a typed name.
    client: Redis = Redis.from_url(
        settings.redis_url,
        password=settings.redis_password.get_secret_value(),
        decode_responses=True,
        socket_connect_timeout=settings.probe_timeout_seconds,
        socket_timeout=settings.probe_timeout_seconds,
        health_check_interval=30,
    )
    return client


async def ping(client: Redis) -> bool:
    return bool(await client.ping())


async def close(client: Redis) -> None:
    await client.aclose()
