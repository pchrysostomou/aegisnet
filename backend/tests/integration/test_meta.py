"""Version metadata and the production-only disclosure controls."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from aegisnet.config import Environment
from aegisnet.main import create_app
from aegisnet.version import APP_VERSION
from tests.conftest import make_settings

pytestmark = pytest.mark.integration

REAL = "production-grade-secret-0123456789"


@pytest.fixture
def production_client() -> Iterator[TestClient]:
    settings = make_settings(
        env=Environment.production,
        secret_key=REAL,
        postgres_app_password=REAL,
        postgres_migrator_password=REAL,
        redis_password=REAL,
    )
    with TestClient(create_app(settings), raise_server_exceptions=False) as client:
        yield client


def test_version_reports_build_metadata(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GIT_SHA", "abc1234")
    body = client.get("/api/v1/meta/version").json()
    assert body == {
        "app_name": "aegisnet",
        "version": APP_VERSION,
        "environment": "test",
        "git_sha": "abc1234",
        "schema_revision": None,
    }


def test_git_sha_is_withheld_in_production(
    production_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GIT_SHA", "abc1234")
    body = production_client.get("/api/v1/meta/version").json()
    assert body["environment"] == "production"
    assert body["git_sha"] is None
    assert "abc1234" not in production_client.get("/api/v1/meta/version").text


def test_interactive_docs_are_served_outside_production(client: TestClient) -> None:
    assert client.get("/docs").status_code == 200
    assert client.get("/openapi.json").status_code == 200
    assert client.get("/redoc").status_code == 404


def test_interactive_docs_are_disabled_in_production(production_client: TestClient) -> None:
    for path in ("/docs", "/openapi.json", "/redoc"):
        assert production_client.get(path).status_code == 404, path
