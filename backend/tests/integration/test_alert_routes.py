"""Alerts and detections over HTTP: reads for viewers, runs for analysts, sweeps for admins."""

from __future__ import annotations

from datetime import timedelta
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from aegisnet.domain.assets import AssetSpec
from tests.detectors.conftest import WINDOW_START, flow_row
from tests.fakes import FakeWiring

pytestmark = pytest.mark.integration

ALERTS = "/api/v1/alerts"
DETECTIONS = "/api/v1/detections"
SCANNER = "10.10.0.99"
SWEEP = {"from": WINDOW_START.isoformat(), "to": (WINDOW_START + timedelta(minutes=20)).isoformat()}


@pytest.fixture
async def swept(wiring: FakeWiring) -> None:
    for offset in range(40):
        row = flow_row(WINDOW_START + timedelta(seconds=offset), SCANNER, "10.10.0.20", offset + 1)
        wiring.event_store.rows[row.id] = row
    await wiring.assets.create(
        AssetSpec.model_validate(
            {
                "hostname": "scanner.lab.example.test",
                "environment": "lab",
                "criticality": 4,
                "networks": [{"cidr": "10.10.0.99/32"}],
            }
        )
    )
    outcome = await wiring.detection.sweep(WINDOW_START, WINDOW_START + timedelta(minutes=20))
    assert outcome.alerts_created == 1 and len(outcome.runs) == 3


@pytest.mark.usefixtures("swept")
def test_viewers_read_alerts_with_filters_and_details(
    client: TestClient, viewer_headers: dict[str, str]
) -> None:
    page = client.get(ALERTS, headers=viewer_headers)
    assert page.status_code == 200, page.text
    [alert] = page.json()["items"]
    assert alert["rule_id"] == "D-001" and alert["entity_value"] == SCANNER
    assert alert["severity"] == 4 and alert["status"] == "open"
    assert alert["severity_rationale"]["result"] == 4 and "payload" not in alert["evidence"]
    assert page.json()["next_cursor"] is None
    assert (
        client.get(ALERTS, params={"severity_min": 5}, headers=viewer_headers).json()["items"] == []
    )
    assert (
        len(
            client.get(
                ALERTS,
                params={"rule_id": "D-001", "entity_type": "src_ip", "entity_value": SCANNER},
                headers=viewer_headers,
            ).json()["items"]
        )
        == 1
    )
    detail = client.get(f"{ALERTS}/{alert['id']}", headers=viewer_headers)
    assert detail.status_code == 200, detail.text
    body = detail.json()
    assert len(body["events"]) == 20 and body["events"][0]["role"] == "first"
    [asset] = body["assets"]
    assert asset["role"] == "source"
    assert client.get(f"{ALERTS}/{uuid4()}", headers=viewer_headers).status_code == 404


@pytest.mark.parametrize(
    "params",
    [
        {"limit": 0},
        {"limit": 201},
        {"cursor": "nope"},
        {"severity_min": 6},
        {"rule_id": "X-1"},
        {"entity_type": "planet"},
        {"status": "bogus"},
        {"from": "2026-09-02T00:00:00Z", "to": "2026-09-01T00:00:00Z"},
    ],
)
def test_alert_query_parameters_are_validated(
    client: TestClient, viewer_headers: dict[str, str], params: dict[str, object]
) -> None:
    assert client.get(ALERTS, params=params, headers=viewer_headers).status_code == 422


@pytest.mark.usefixtures("swept")
def test_rules_and_runs(
    client: TestClient, viewer_headers: dict[str, str], analyst_headers: dict[str, str]
) -> None:
    rules = client.get(f"{DETECTIONS}/rules", headers=viewer_headers)
    assert rules.status_code == 200, rules.text
    assert [r["rule_id"] for r in rules.json()] == ["D-001", "D-002", "D-003"]
    rule = rules.json()[0]
    assert rule["version"] == 1 and rule["enabled"] is True
    assert rule["params"]["distinct_ports"] == 20
    assert client.get(f"{DETECTIONS}/runs", headers=viewer_headers).status_code == 403
    runs = client.get(f"{DETECTIONS}/runs", params={"limit": 5}, headers=analyst_headers)
    assert runs.status_code == 200, runs.text
    assert {r["rule_id"] for r in runs.json()} == {"D-001", "D-002", "D-003"}
    [run] = [r for r in runs.json() if r["rule_id"] == "D-001"]
    assert run["status"] == "success" and run["alerts_created"] == 1
    assert (
        client.get(f"{DETECTIONS}/runs", params={"limit": 0}, headers=analyst_headers).status_code
        == 422
    )


def test_rules_are_seeded_on_first_read(client: TestClient, viewer_headers: dict[str, str]) -> None:
    rules = client.get(f"{DETECTIONS}/rules", headers=viewer_headers)
    assert rules.status_code == 200
    assert [r["rule_id"] for r in rules.json()] == ["D-001", "D-002", "D-003"]


def test_sweeps_are_queued_by_admins_only_and_audited(
    client: TestClient,
    wiring: FakeWiring,
    analyst_headers: dict[str, str],
    admin_headers: dict[str, str],
) -> None:
    assert (
        client.post(f"{DETECTIONS}/sweeps", json=SWEEP, headers=analyst_headers).status_code == 403
    )
    accepted = client.post(f"{DETECTIONS}/sweeps", json=SWEEP, headers=admin_headers)
    assert accepted.status_code == 202, accepted.text
    assert accepted.json()["queued"] is True and accepted.json()["message_id"] == "sweep-1"
    assert wiring.sweeps == [(WINDOW_START, WINDOW_START + timedelta(minutes=20))]
    entry = wiring.audit_store.entries[-1]
    assert entry.action == "detection.sweep_requested" and entry.target_id == "sweep-1"
    for bad in (
        {"from": SWEEP["to"], "to": SWEEP["from"]},
        {"from": "2026-09-01T00:00:00", "to": "2026-09-01T01:00:00"},
        {"from": SWEEP["from"], "to": (WINDOW_START + timedelta(hours=25)).isoformat()},
        {"from": SWEEP["from"]},
        {"from": SWEEP["from"], "to": SWEEP["to"], "extra": 1},
    ):
        assert (
            client.post(f"{DETECTIONS}/sweeps", json=bad, headers=admin_headers).status_code == 422
        ), bad
    assert len(wiring.sweeps) == 1
