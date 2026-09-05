"""The audit trail over HTTP: admin only, newest first, filters and cursors."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from tests.fakes import FakeWiring

pytestmark = pytest.mark.integration

AUDIT = "/api/v1/audit"
ASSET = {
    "hostname": "h.lab.example.test",
    "environment": "lab",
    "networks": [{"cidr": "10.0.0.0/24"}],
}


def test_admins_read_the_trail_newest_first_with_filters_and_cursors(
    client: TestClient,
    wiring: FakeWiring,
    admin_headers: dict[str, str],
    viewer_headers: dict[str, str],
) -> None:
    admin_id, viewer_id = (str(user.id) for user in wiring.users.rows.values())
    assert client.get(AUDIT, headers=viewer_headers).status_code == 403  # audited itself
    created = client.post("/api/v1/assets", json=ASSET, headers=admin_headers)
    assert created.status_code == 201
    asset_id = created.json()["id"]
    patched = client.patch(f"/api/v1/assets/{asset_id}", json={"owner": "x"}, headers=admin_headers)
    assert patched.status_code == 200
    assert wiring.audit_actions() == ["rbac.denied", "asset.created", "asset.updated"]

    page = client.get(AUDIT, params={"limit": 2}, headers=admin_headers)
    assert page.status_code == 200, page.text
    items = page.json()["items"]
    assert [i["action"] for i in items] == ["asset.updated", "asset.created"]
    assert items[0]["id"] > items[1]["id"]
    assert items[0]["actor_user_id"] == admin_id and items[0]["actor_token_id"] is None
    assert items[0]["target_type"] == "asset" and items[0]["target_id"] == asset_id
    assert items[0]["detail"] == {"before": {"owner": None}, "after": {"owner": "x"}}
    assert items[0]["correlation_id"]
    cursor = page.json()["next_cursor"]
    assert cursor
    rest = client.get(AUDIT, params={"limit": 2, "cursor": cursor}, headers=admin_headers)
    [denied] = rest.json()["items"]
    assert rest.json()["next_cursor"] is None
    assert denied["action"] == "rbac.denied" and denied["result"] == "denied"
    assert denied["target_id"] == f"GET {AUDIT}" and denied["actor_user_id"] == viewer_id
    assert denied["detail"] == {"permission": "audit.read", "role": "viewer"}

    by_result = client.get(AUDIT, params={"result": "denied"}, headers=admin_headers).json()
    assert [i["action"] for i in by_result["items"]] == ["rbac.denied"]
    by_action = client.get(AUDIT, params={"action": "asset.created"}, headers=admin_headers)
    assert [i["action"] for i in by_action.json()["items"]] == ["asset.created"]
    by_actor = client.get(AUDIT, params={"actor": viewer_id}, headers=admin_headers).json()
    assert [i["action"] for i in by_actor["items"]] == ["rbac.denied"]


@pytest.mark.parametrize(
    "params",
    [{"limit": 0}, {"limit": 201}, {"cursor": "nope"}, {"result": "bogus"}, {"actor": "x"}],
)
def test_query_parameters_are_validated(
    client: TestClient, admin_headers: dict[str, str], params: dict[str, object]
) -> None:
    assert client.get(AUDIT, params=params, headers=admin_headers).status_code == 422
