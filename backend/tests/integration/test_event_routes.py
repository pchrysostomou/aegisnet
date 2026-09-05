"""Event reads over HTTP: the window rules, payload gating by role, single rows, stats."""

from __future__ import annotations

from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from aegisnet.domain.enums import EventType
from tests.fakes import FakeWiring, event_row_stub

pytestmark = pytest.mark.integration

EVENTS = "/api/v1/events"
WINDOW = {"from": "2026-09-01T00:00:00Z", "to": "2026-09-02T00:00:00Z"}


def test_the_window_is_required_and_bounded(
    client: TestClient, viewer_headers: dict[str, str]
) -> None:
    assert client.get(EVENTS, headers=viewer_headers).status_code == 422
    too_long = {"from": "2026-08-01T00:00:00Z", "to": "2026-09-02T00:00:00Z"}
    response = client.get(EVENTS, params=too_long, headers=viewer_headers)
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_failed"
    naive = {"from": "2026-09-01T00:00:00", "to": "2026-09-02T00:00:00"}
    assert client.get(EVENTS, params=naive, headers=viewer_headers).status_code == 422
    backwards = {"from": WINDOW["to"], "to": WINDOW["from"]}
    assert client.get(EVENTS, params=backwards, headers=viewer_headers).status_code == 422
    assert (
        client.get(EVENTS, params={**WINDOW, "limit": 201}, headers=viewer_headers).status_code
        == 422
    )
    assert (
        client.get(EVENTS, params={**WINDOW, "cursor": "nope"}, headers=viewer_headers).status_code
        == 422
    )
    assert (
        client.get(
            EVENTS, params={**WINDOW, "dest_port": 70000}, headers=viewer_headers
        ).status_code
        == 422
    )


def test_payloads_are_requested_only_for_roles_that_may_see_them(
    client: TestClient,
    wiring: FakeWiring,
    viewer_headers: dict[str, str],
    analyst_headers: dict[str, str],
) -> None:
    row = event_row_stub(payload={"dns": {"rrname": "www.example.test"}})
    wiring.event_store.rows[row.id] = row
    seen = client.get(EVENTS, params=WINDOW, headers=viewer_headers)
    assert seen.status_code == 200, seen.text
    assert "x-query-duration-ms" in seen.headers
    assert wiring.event_store.queries[-1].include_payload is False
    assert [e["id"] for e in seen.json()["items"]] == [str(row.id)]
    full = client.get(
        EVENTS,
        params={**WINDOW, "event_type": ["dns", "flow"], "dest_port": [53], "flow_id": 1},
        headers=analyst_headers,
    )
    assert full.status_code == 200, full.text
    query = wiring.event_store.queries[-1]
    assert query.include_payload is True and query.dest_ports == (53,) and query.flow_id == 1
    assert query.event_types == (EventType.dns, EventType.flow)
    bogus = client.get(EVENTS, params={**WINDOW, "event_type": "bogus"}, headers=analyst_headers)
    assert bogus.status_code == 422


def test_single_events_and_stats(
    client: TestClient,
    wiring: FakeWiring,
    viewer_headers: dict[str, str],
    analyst_headers: dict[str, str],
) -> None:
    row = event_row_stub(payload={"dns": {"rrname": "www.example.test"}})
    wiring.event_store.rows[row.id] = row
    assert client.get(f"{EVENTS}/{row.id}", headers=viewer_headers).status_code == 403
    one = client.get(f"{EVENTS}/{row.id}", headers=analyst_headers)
    assert one.status_code == 200, one.text
    assert one.json()["payload"] == {"dns": {"rrname": "www.example.test"}}
    assert one.json()["dns_query"] == "www.example.test"
    assert client.get(f"{EVENTS}/{uuid4()}", headers=analyst_headers).status_code == 404
    stats = client.get(f"{EVENTS}/stats", params=WINDOW, headers=viewer_headers)
    assert stats.status_code == 200, stats.text
    assert set(stats.json()) == {"total", "by_type", "by_hour"}
    assert client.get(f"{EVENTS}/stats", headers=viewer_headers).status_code == 422
