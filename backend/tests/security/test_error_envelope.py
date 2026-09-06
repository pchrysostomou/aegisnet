"""T-2.7: errors disclose neither tracebacks, nor SQL, nor paths — only the documented envelope."""

from __future__ import annotations

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from sqlalchemy.exc import DBAPIError

from aegisnet.api.errors import GENERIC_SERVER_MESSAGE

pytestmark = pytest.mark.security

ENVELOPE_KEYS = {"code", "message", "correlation_id", "details"}
LEAK_MARKERS = ("Traceback", 'File "', "/etc/passwd", "SELECT", "RuntimeError", "site-packages")


@pytest.fixture
def leaky_app(app: FastAPI) -> FastAPI:
    @app.get("/_test/boom")
    async def _boom() -> None:
        raise RuntimeError("SELECT * FROM users; see /etc/passwd")

    @app.get("/_test/validate")
    async def _validate(limit: int) -> dict[str, int]:
        return {"limit": limit}

    @app.get("/_test/teapot")
    async def _teapot() -> None:
        raise HTTPException(status_code=418, detail="short and stout", headers={"X-Extra": "1"})

    return app


def _error(response_json: dict[str, object]) -> dict[str, object]:
    assert set(response_json) == {"error"}
    error = response_json["error"]
    assert isinstance(error, dict)
    assert set(error) == ENVELOPE_KEYS
    return error


@pytest.mark.usefixtures("leaky_app")
def test_unhandled_exceptions_become_a_generic_500(client: TestClient) -> None:
    response = client.get("/_test/boom")
    assert response.status_code == 500
    error = _error(response.json())
    assert error["code"] == "internal_error"
    assert error["message"] == GENERIC_SERVER_MESSAGE
    assert error["details"] == []
    for marker in LEAK_MARKERS:
        assert marker not in response.text


@pytest.mark.usefixtures("leaky_app")
def test_validation_failures_name_the_field_only(client: TestClient) -> None:
    response = client.get("/_test/validate", params={"limit": "ten"})
    assert response.status_code == 422
    error = _error(response.json())
    assert error["code"] == "validation_failed"
    details = error["details"]
    assert isinstance(details, list)
    assert [d["field"] for d in details] == ["query.limit"]
    assert isinstance(details[0]["issue"], str)
    assert details[0]["issue"]
    assert "Traceback" not in response.text


def test_not_found_uses_the_envelope(client: TestClient) -> None:
    response = client.get("/nope")
    assert response.status_code == 404
    error = _error(response.json())
    assert error["code"] == "not_found"


def test_method_not_allowed_uses_the_envelope(client: TestClient) -> None:
    response = client.post("/healthz")
    assert response.status_code == 405
    assert _error(response.json())["code"] == "http_error"


@pytest.mark.usefixtures("leaky_app")
def test_http_exception_headers_are_preserved(client: TestClient) -> None:
    response = client.get("/_test/teapot")
    assert response.status_code == 418
    assert response.headers["X-Extra"] == "1"
    assert _error(response.json())["message"] == "short and stout"


@pytest.mark.parametrize(
    ("status", "code"),
    [
        (401, "unauthenticated"),
        (403, "forbidden"),
        (408, "request_timeout"),
        (409, "conflict"),
        (413, "payload_too_large"),
        (429, "rate_limited"),
        (503, "service_unavailable"),
    ],
)
def test_known_statuses_map_to_stable_codes(
    app: FastAPI, client: TestClient, status: int, code: str
) -> None:
    @app.get(f"/_test/status/{status}")
    async def _raise() -> None:
        raise HTTPException(status_code=status)

    response = client.get(f"/_test/status/{status}")
    assert response.status_code == status
    assert _error(response.json())["code"] == code


class _Cancelled:
    """What asyncpg puts on `DBAPIError.orig` when `statement_timeout` fires."""

    sqlstate = "57014"


def test_a_cancelled_statement_is_a_service_unavailable_and_not_a_500(
    app: FastAPI, client: TestClient
) -> None:
    """T-2.6: the bound is only useful if what comes back is the documented envelope. A raw
    `DBAPIError` would reach the generic 500 path, which is safe but says the wrong thing — a
    cancelled statement is a query that asked for too much, and a narrower one is worth trying.
    """

    @app.get("/_test/slow-query")
    async def _slow() -> None:
        raise DBAPIError("SELECT …", {"secret": "value"}, _Cancelled())

    response = client.get("/_test/slow-query")

    assert response.status_code == 503
    body = _error(response.json())
    assert body["code"] == "service_unavailable"
    assert body["correlation_id"]
    # Nothing about the statement or its parameters comes back.
    assert "SELECT" not in response.text and "secret" not in response.text


def test_every_other_database_error_is_still_a_generic_500(
    app: FastAPI, client: TestClient
) -> None:
    """The handler must not turn every driver failure into a 503: a broken connection or a
    constraint violation is not a query that asked for too much."""

    class _Broken:
        sqlstate = "08006"  # connection_failure

    @app.get("/_test/broken-db")
    async def _broken() -> None:
        raise DBAPIError("SELECT …", {}, _Broken())

    response = client.get("/_test/broken-db")

    assert response.status_code == 500
    assert _error(response.json())["code"] == "internal_error"
