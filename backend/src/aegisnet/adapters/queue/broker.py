"""Dramatiq broker factory.

**No actors are declared here.** Actors are entrypoints and live in
``aegisnet.workers.actors``; the process entrypoint the ``dramatiq`` CLI loads is
``aegisnet.workers.main`` (ADR-014). The worker's container healthcheck is process-level
liveness only and asserts nothing about capability (ADR-010).

This module is a pure factory with no import-time side effects, so it can be imported and
tested without a running Redis.
"""

from __future__ import annotations

import dramatiq
import redis
from dramatiq.brokers.redis import RedisBroker

from aegisnet.config import Settings, get_settings


def build_redis_client(settings: Settings) -> redis.Redis:
    """Synchronous Redis client for the broker, authenticated from settings.

    The client is built explicitly rather than via ``RedisBroker(url=..., password=...)``.
    When ``url`` is given, Dramatiq creates its own ``ConnectionPool.from_url(url)`` and
    passes it to ``redis.Redis`` together with the remaining keyword arguments; redis-py
    ignores ``password`` whenever a pool is supplied, so the worker would have connected
    unauthenticated and failed with NOAUTH against the password-protected server.
    """
    return redis.Redis(
        host=settings.redis_host,
        port=settings.redis_port,
        db=0,
        password=settings.redis_password.get_secret_value(),
        socket_connect_timeout=settings.probe_timeout_seconds,
        socket_timeout=settings.probe_timeout_seconds,
    )


def build_broker(settings: Settings) -> RedisBroker:
    # Dramatiq ships no annotations for RedisBroker.__init__, so the call is untyped.
    # The ignore is narrow and deliberate rather than a project-wide mypy relaxation.
    return RedisBroker(client=build_redis_client(settings))  # type: ignore[no-untyped-call]


def install(settings: Settings | None = None) -> RedisBroker:
    """Create the broker and register it as the process-wide default."""
    resolved = settings or get_settings()
    broker = build_broker(resolved)
    dramatiq.set_broker(broker)
    return broker
