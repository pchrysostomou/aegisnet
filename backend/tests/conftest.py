"""Shared fixtures.

Chunk 1 tests are hermetic: no PostgreSQL, no Redis, no network. Readiness probes are
replaced with in-process fakes, and the security tests read the committed manifests as
data.
"""

from __future__ import annotations

import os

# ``aegisnet.main`` builds the module-level ``app`` on import via ``get_settings()``, which
# refuses placeholder secrets outside ENV=test. Setting it here, before any test module
# imports the package, keeps collection independent of the developer's shell.
os.environ.setdefault("ENV", "test")

from collections.abc import Awaitable, Callable, Iterator
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from aegisnet.config import Environment, Settings
from aegisnet.domain.enums import UserRole
from aegisnet.main import create_app
from tests.fakes import FakeWiring

REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND_ROOT = REPO_ROOT / "backend"

SECRET_ENV_VARS = (
    "SECRET_KEY",
    "POSTGRES_APP_PASSWORD",
    "POSTGRES_MIGRATOR_PASSWORD",
    "REDIS_PASSWORD",
)

Probe = Callable[[], Awaitable[bool]]

# Long enough for HS256, derived rather than literal so no secret-shaped string sits in
# the repository for a scanner to trip on.
TEST_SECRET_KEY = "test-signing-key-" + "0" * 32


def make_settings(**overrides: object) -> Settings:
    """Settings that never read a ``.env`` file, so results do not depend on the host."""
    values: dict[str, object] = {"env": Environment.test}
    values.update(overrides)
    return Settings(_env_file=None, **values)  # type: ignore[arg-type]


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    # cookie_secure=False: the test client speaks plain http to "testserver"; a separate
    # test asserts the flag is on by default.
    return make_settings(
        cookie_secure=False,
        spool_dir=tmp_path / "spool",
        secret_key=TEST_SECRET_KEY,
    )


@pytest.fixture
def wiring(settings: Settings) -> FakeWiring:
    """In-memory ports behind the real routes; inspect ``wiring.audit_store`` etc."""
    return FakeWiring(settings, settings.spool_dir)


@pytest.fixture
def app(settings: Settings, wiring: FakeWiring) -> FastAPI:
    return create_app(settings, services_factory=wiring.factory())  # type: ignore[arg-type]


@pytest.fixture
def client(app: FastAPI) -> Iterator[TestClient]:
    # ``raise_server_exceptions=False`` lets the error-envelope tests observe the 500
    # response instead of the exception. The context manager runs the lifespan.
    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client


async def probe_ok() -> bool:
    return True


@pytest.fixture
def healthy_probes(app: FastAPI, client: TestClient) -> dict[str, Probe]:
    """Replace the real connectivity probes with fakes that succeed."""
    probes: dict[str, Probe] = {"postgres": probe_ok, "redis": probe_ok}
    app.state.readiness_probes = probes
    return probes


@pytest.fixture
def no_secret_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Guarantee the process environment supplies no secret values."""
    for name in SECRET_ENV_VARS:
        monkeypatch.delenv(name, raising=False)


PASSWORD = "correct horse battery"


async def _headers_for(wiring: FakeWiring, role: UserRole) -> dict[str, str]:
    email = f"{role.value}@example.test"
    if await wiring.users.get_by_email(email) is None:
        await wiring.add_user(email, role, PASSWORD)
    return await wiring.login_headers(email, PASSWORD)


@pytest.fixture
async def admin_headers(wiring: FakeWiring) -> dict[str, str]:
    return await _headers_for(wiring, UserRole.admin)


@pytest.fixture
async def analyst_headers(wiring: FakeWiring) -> dict[str, str]:
    return await _headers_for(wiring, UserRole.analyst)


@pytest.fixture
async def viewer_headers(wiring: FakeWiring) -> dict[str, str]:
    return await _headers_for(wiring, UserRole.viewer)


@pytest.fixture
async def service_headers(wiring: FakeWiring) -> dict[str, str]:
    return await wiring.service_token_headers()
