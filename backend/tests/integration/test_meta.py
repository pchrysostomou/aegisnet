"""Version metadata and the production-only disclosure controls."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from aegisnet.config import Environment
from aegisnet.main import create_app
from aegisnet.version import APP_VERSION, schema_revision
from tests.conftest import make_settings
from tests.fakes import FakeWiring

pytestmark = pytest.mark.integration

REAL = "production-grade-secret-0123456789"


@pytest.fixture
def production_wiring(tmp_path: object) -> FakeWiring:
    settings = make_settings(
        env=Environment.production,
        secret_key=REAL,
        postgres_app_password=REAL,
        postgres_migrator_password=REAL,
        redis_password=REAL,
    )
    return FakeWiring(settings, settings.spool_dir)


@pytest.fixture
def production_client(production_wiring: FakeWiring) -> Iterator[TestClient]:
    app = create_app(production_wiring.settings, services_factory=production_wiring.factory())  # type: ignore[arg-type]
    with TestClient(app, raise_server_exceptions=False) as client:
        yield client


def test_version_requires_authentication(client: TestClient) -> None:
    response = client.get("/api/v1/meta/version")
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"
    assert response.json()["error"]["code"] == "unauthenticated"


def test_version_reports_build_metadata(
    client: TestClient, viewer_headers: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GIT_SHA", "abc1234")
    body = client.get("/api/v1/meta/version", headers=viewer_headers).json()
    assert body == {
        "app_name": "aegisnet",
        "version": APP_VERSION,
        "environment": "test",
        "git_sha": "abc1234",
        "schema_revision": schema_revision(),
    }
    assert body["schema_revision"] == "0003_detection_tables"


async def test_git_sha_is_withheld_in_production(
    production_client: TestClient, production_wiring: FakeWiring, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GIT_SHA", "abc1234")
    headers = await production_wiring.service_token_headers()
    body = production_client.get("/api/v1/meta/version", headers=headers).json()
    assert body["environment"] == "production"
    assert body["git_sha"] is None
    assert "abc1234" not in production_client.get("/api/v1/meta/version", headers=headers).text


def test_interactive_docs_are_served_outside_production(client: TestClient) -> None:
    assert client.get("/docs").status_code == 200
    assert client.get("/openapi.json").status_code == 200
    assert client.get("/redoc").status_code == 404


def test_interactive_docs_are_disabled_in_production(production_client: TestClient) -> None:
    for path in ("/docs", "/openapi.json", "/redoc"):
        assert production_client.get(path).status_code == 404, path
