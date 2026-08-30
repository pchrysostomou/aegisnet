"""Correlation-ID propagation: accepted for tracing, never trusted as content."""

from __future__ import annotations

import uuid

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from aegisnet.logging import correlation_id_var
from aegisnet.main import CORRELATION_HEADER

pytestmark = pytest.mark.integration


def test_every_response_carries_a_correlation_id(client: TestClient) -> None:
    for path in ("/healthz", "/does-not-exist"):
        value = client.get(path).headers[CORRELATION_HEADER]
        assert uuid.UUID(value)


def test_a_well_formed_inbound_id_is_echoed(client: TestClient) -> None:
    supplied = str(uuid.uuid4())
    response = client.get("/healthz", headers={CORRELATION_HEADER: supplied})
    assert response.headers[CORRELATION_HEADER] == supplied


@pytest.mark.parametrize(
    "hostile",
    ["not-a-uuid", "", "1\n2", "\x1b[2J", "' OR 1=1 --", "a" * 4096],
)
def test_a_malformed_inbound_id_is_replaced(client: TestClient, hostile: str) -> None:
    response = client.get("/healthz", headers={CORRELATION_HEADER: hostile})
    echoed = response.headers[CORRELATION_HEADER]
    assert echoed != hostile
    assert uuid.UUID(echoed)


def test_error_envelope_id_matches_the_response_header(client: TestClient) -> None:
    response = client.get("/does-not-exist")
    assert response.json()["error"]["correlation_id"] == response.headers[CORRELATION_HEADER]


def test_the_id_is_visible_to_handlers_and_cleared_afterwards(
    app: FastAPI, client: TestClient
) -> None:
    seen: list[str | None] = []

    @app.get("/_test/cid")
    async def _cid() -> dict[str, str | None]:
        seen.append(correlation_id_var.get())
        return {"cid": seen[-1]}

    supplied = str(uuid.uuid4())
    body = client.get("/_test/cid", headers={CORRELATION_HEADER: supplied}).json()
    assert body["cid"] == supplied
    assert seen == [supplied]
    assert correlation_id_var.get() is None
