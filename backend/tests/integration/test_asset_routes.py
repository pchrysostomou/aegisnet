"""The asset inventory over HTTP: CRUD with an audit trail, conflicts, bulk, resolution."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from tests.fakes import FakeWiring

pytestmark = pytest.mark.integration

ASSETS = "/api/v1/assets"


def _spec(hostname: str | None, *cidrs: str, **extra: Any) -> dict[str, Any]:
    return {
        "hostname": hostname,
        "environment": "lab",
        "networks": [{"cidr": cidr} for cidr in cidrs],
        **extra,
    }


def test_create_read_update_deactivate_with_an_audit_trail(
    client: TestClient,
    wiring: FakeWiring,
    analyst_headers: dict[str, str],
    admin_headers: dict[str, str],
) -> None:
    created = client.post(
        ASSETS,
        json=_spec("web-1.lab.example.test", "10.10.1.0/24", owner="blue"),
        headers=analyst_headers,
    )
    assert created.status_code == 201, created.text
    asset = created.json()
    assert asset["hostname"] == "web-1.lab.example.test" and asset["is_active"]
    assert asset["networks"][0]["cidr"] == "10.10.1.0/24"
    entry = wiring.audit_store.entries[-1]
    assert entry.action == "asset.created" and entry.target_id == asset["id"]
    assert entry.detail["networks"] == ["10.10.1.0/24"] and entry.actor_user_id is not None

    got = client.get(f"{ASSETS}/{asset['id']}", headers=analyst_headers)
    assert got.status_code == 200 and got.json() == asset

    patched = client.patch(
        f"{ASSETS}/{asset['id']}", json={"owner": "red"}, headers=analyst_headers
    )
    assert patched.status_code == 200, patched.text
    assert patched.json()["owner"] == "red"
    entry = wiring.audit_store.entries[-1]
    assert entry.action == "asset.updated"
    assert entry.detail == {"before": {"owner": "blue"}, "after": {"owner": "red"}}

    assert client.delete(f"{ASSETS}/{asset['id']}", headers=analyst_headers).status_code == 403
    gone = client.delete(f"{ASSETS}/{asset['id']}", headers=admin_headers)
    assert gone.status_code == 200 and gone.json()["is_active"] is False
    assert wiring.audit_store.entries[-1].action == "asset.deactivated"
    assert client.get(ASSETS, headers=analyst_headers).json()["items"] == []
    inactive = client.get(ASSETS, params={"include_inactive": "true"}, headers=analyst_headers)
    assert [a["id"] for a in inactive.json()["items"]] == [asset["id"]]
    assert (
        client.patch(
            f"{ASSETS}/{uuid4()}", json={"owner": "x"}, headers=analyst_headers
        ).status_code
        == 404
    )


def test_conflicts_are_409_with_a_specific_code(
    client: TestClient, analyst_headers: dict[str, str]
) -> None:
    first = client.post(
        ASSETS, json=_spec("db-1.lab.example.test", "10.10.2.0/24"), headers=analyst_headers
    )
    assert first.status_code == 201
    duplicate = client.post(
        ASSETS, json=_spec("DB-1.lab.example.test", "10.10.3.0/24"), headers=analyst_headers
    )
    assert duplicate.status_code == 409 and duplicate.json()["error"]["code"] == "conflict"
    overlap = client.post(
        ASSETS, json=_spec("db-2.lab.example.test", "10.10.2.128/25"), headers=analyst_headers
    )
    assert overlap.status_code == 409
    assert overlap.json()["error"]["code"] == "network_overlap"


def test_bulk_creation_is_admin_only(
    client: TestClient, analyst_headers: dict[str, str], admin_headers: dict[str, str]
) -> None:
    body = {
        "assets": [
            _spec("a.lab.example.test", "10.20.0.0/24"),
            _spec("b.lab.example.test", "10.20.1.0/24"),
        ]
    }
    assert client.post(f"{ASSETS}/bulk", json=body, headers=analyst_headers).status_code == 403
    created = client.post(f"{ASSETS}/bulk", json=body, headers=admin_headers)
    assert created.status_code == 201, created.text
    hostnames = [a["hostname"] for a in created.json()["created"]]
    assert hostnames == ["a.lab.example.test", "b.lab.example.test"]
    clash = {"assets": [_spec("c.lab.example.test", "10.20.0.0/25")]}
    assert client.post(f"{ASSETS}/bulk", json=clash, headers=admin_headers).status_code == 409
    assert len(client.get(ASSETS, headers=admin_headers).json()["items"]) == 2
    empty = client.post(f"{ASSETS}/bulk", json={"assets": []}, headers=admin_headers)
    assert empty.status_code == 422


def test_bodies_are_validated_before_the_service(
    client: TestClient, analyst_headers: dict[str, str]
) -> None:
    bad = [
        {"environment": "lab", "surprise": 1},
        {"environment": "moon"},
        _spec("bad host name", "10.0.0.0/24"),
        _spec("h.lab.example.test", "10.0.0.1/24"),
        _spec("h.lab.example.test", "10.0.0.0/24", criticality=9),
    ]
    for body in bad:
        response = client.post(ASSETS, json=body, headers=analyst_headers)
        assert response.status_code == 422, body
        assert response.json()["error"]["code"] == "validation_failed"


def test_resolution_and_lookups(
    client: TestClient, admin_headers: dict[str, str], viewer_headers: dict[str, str]
) -> None:
    body = {
        "assets": [
            _spec("web.lab.example.test", "10.30.0.0/24"),
            _spec("db.lab.example.test", "10.30.1.0/24", environment="staging"),
        ]
    }
    assert client.post(f"{ASSETS}/bulk", json=body, headers=admin_headers).status_code == 201
    listed = client.get(ASSETS, headers=viewer_headers)
    assert listed.status_code == 200 and len(listed.json()["items"]) == 2
    assert client.get(ASSETS, params={"tag": "Bad Tag"}, headers=viewer_headers).status_code == 422
    assert client.get(ASSETS, params={"limit": 201}, headers=viewer_headers).status_code == 422
    hit = client.get(f"{ASSETS}/resolve", params={"ip": "10.30.1.7"}, headers=viewer_headers)
    assert hit.status_code == 200, hit.text
    assert hit.json()["matched"] and hit.json()["matched_cidr"] == "10.30.1.0/24"
    assert hit.json()["asset"]["hostname"] == "db.lab.example.test"
    miss = client.get(f"{ASSETS}/resolve", params={"ip": "192.0.2.1"}, headers=viewer_headers)
    assert miss.json() == {"matched": False, "ip": "192.0.2.1", "asset": None, "matched_cidr": None}
    bad_ip = client.get(f"{ASSETS}/resolve", params={"ip": "not-an-ip"}, headers=viewer_headers)
    assert bad_ip.status_code == 422
    assert client.get(f"{ASSETS}/{uuid4()}", headers=viewer_headers).status_code == 404
    forbidden = client.post(ASSETS, json=_spec("x.lab.example.test"), headers=viewer_headers)
    assert forbidden.status_code == 403
