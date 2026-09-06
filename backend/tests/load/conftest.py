"""Fixtures for the load suite.

Opt-in only, like the database suite. It runs when ``AEGISNET_LOAD_TESTS=1`` and an API is
listening at ``AEGISNET_API_PUBLIC_URL``, which is what ``make load-test`` arranges; otherwise
every test marked ``load`` is skipped and the default suite stays hermetic.

This suite is the only one that deliberately exhausts a real rate limiter, so it cleans up
after itself: the login limits are per-IP and fail closed, and leaving them spent would lock
the operator out of their own stack for fifteen minutes. Every test that burns a key deletes
it, and a session fixture sweeps at the end in case one died first.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator, Iterator

import httpx
import pytest
from redis.asyncio import Redis

from aegisnet.config import Settings
from tests.conftest import make_settings

LOAD_FLAG = "AEGISNET_LOAD_TESTS"
API_URL = os.environ.get("AEGISNET_API_PUBLIC_URL", "http://127.0.0.1:8000")
EMAIL = os.environ.get("AEGISNET_E2E_ANALYST", "")
PASSWORD = os.environ.get("AEGISNET_E2E_ANALYST_PASSWORD", "")


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if os.environ.get(LOAD_FLAG) == "1":
        return
    skip = pytest.mark.skip(
        reason=f"load suite: set {LOAD_FLAG}=1 against a running stack (make load-test)"
    )
    for item in items:
        if "load" in item.keywords:
            item.add_marker(skip)


@pytest.fixture(scope="session")
def load_settings() -> Settings:
    """Reads the process environment, never a .env file — the same rule the db suite follows."""
    return make_settings()


@pytest.fixture
async def api() -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient(base_url=API_URL, timeout=30.0) as client:
        yield client


@pytest.fixture
async def redis(load_settings: Settings) -> AsyncIterator[Redis]:
    client = Redis.from_url(
        load_settings.redis_url, password=load_settings.redis_password.get_secret_value()
    )
    try:
        yield client
    finally:
        await client.aclose()


@pytest.fixture
async def token(api: httpx.AsyncClient) -> str:
    """One sign-in for the session's worth of requests. Signing in per test would spend the
    login budget this suite exists to measure."""
    if not EMAIL or not PASSWORD:
        pytest.skip("set AEGISNET_E2E_ANALYST and AEGISNET_E2E_ANALYST_PASSWORD")
    response = await api.post("/api/v1/auth/login", json={"email": EMAIL, "password": PASSWORD})
    if response.status_code != 200:
        pytest.skip(f"could not sign in ({response.status_code}); is the stack seeded?")
    return str(response.json()["access_token"])


@pytest.fixture(scope="session", autouse=True)
def sweep_login_limits() -> Iterator[None]:
    """The limits this suite spends are real. Leaving them spent would lock the operator out of
    their own stack, so they go at the end whatever happened."""
    yield
    import asyncio

    async def clear() -> None:
        settings = make_settings()
        client = Redis.from_url(
            settings.redis_url, password=settings.redis_password.get_secret_value()
        )
        try:
            keys = [key async for key in client.scan_iter(match="aegisnet:rl:*")]
            if keys:
                await client.delete(*keys)
        finally:
            await client.aclose()

    asyncio.run(clear())
