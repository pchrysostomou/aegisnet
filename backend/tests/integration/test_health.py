"""Liveness and readiness semantics (decision F-15: no dependency detail to anonymous callers)."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from aegisnet.main import create_app
from tests.conftest import TEST_SECRET_KEY, Probe, make_settings, probe_ok
from tests.fakes import FakeWiring

pytestmark = pytest.mark.integration


async def probe_raises() -> bool:
    raise ConnectionError("dial tcp: redis.internal:6379 refused")


async def probe_false() -> bool:
    return False


def test_healthz_is_liveness_only(client: TestClient) -> None:
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


@pytest.mark.usefixtures("healthy_probes")
def test_readyz_is_ok_when_every_dependency_answers(client: TestClient) -> None:
    response = client.get("/readyz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


@pytest.mark.parametrize("failing", [probe_raises, probe_false])
def test_readyz_is_503_when_any_dependency_fails(
    app: FastAPI, client: TestClient, failing: Probe
) -> None:
    app.state.readiness_probes = {"postgres": probe_ok, "redis": failing}
    response = client.get("/readyz")
    assert response.status_code == 503
    assert response.json() == {"status": "degraded"}


def test_readyz_discloses_no_component_names_or_errors(app: FastAPI, client: TestClient) -> None:
    app.state.readiness_probes = {"postgres": probe_raises, "redis": probe_ok}
    body = client.get("/readyz").text.lower()
    for word in ("postgres", "redis", "refused", "dial", "internal"):
        assert word not in body


def test_readyz_times_out_a_hung_dependency(tmp_path: Path) -> None:
    settings = make_settings(
        probe_timeout_seconds=0.05,
        secret_key=TEST_SECRET_KEY,
        spool_dir=tmp_path,
    )
    wiring = FakeWiring(settings, tmp_path)
    app = create_app(settings, services_factory=wiring.factory())  # type: ignore[arg-type]

    async def hangs() -> bool:
        await asyncio.sleep(5)
        return True

    with TestClient(app) as client:
        app.state.readiness_probes = {"postgres": probe_ok, "redis": hangs}
        response = client.get("/readyz")
    assert response.status_code == 503
    assert response.json() == {"status": "degraded"}


def test_lifespan_registers_exactly_postgres_and_redis(app: FastAPI, client: TestClient) -> None:
    """Readiness covers PostgreSQL and Redis only; the worker is not part of it (ADR-010)."""
    assert set(app.state.readiness_probes) == {"postgres", "redis"}
