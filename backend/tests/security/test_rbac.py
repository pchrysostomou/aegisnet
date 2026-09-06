"""Deny by default (T-2.1, T-2.2): every route names a permission, the matrix holds for
each role, a bad credential is never downgraded to anonymous, and each denial is audited."""

from __future__ import annotations

import dataclasses
from typing import Any
from uuid import UUID

import pytest
from fastapi import FastAPI
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from aegisnet.domain.auth import ROLE_PERMISSIONS, Permission
from aegisnet.domain.enums import UserRole
from tests.fakes import FakeWiring

pytestmark = pytest.mark.security

PUBLIC_ROUTES = {
    ("GET", "/healthz"),
    ("GET", "/readyz"),
    ("POST", "/api/v1/auth/login"),
    ("POST", "/api/v1/auth/refresh"),
}
ZERO = UUID(int=0)
WINDOW = {"from": "2026-09-01T00:00:00Z", "to": "2026-09-02T00:00:00Z"}
ASSET = {"environment": "lab", "networks": [{"cidr": "10.9.0.0/24"}]}
BULK = {"assets": [{"environment": "lab", "networks": [{"cidr": "10.8.0.0/24"}]}]}

Case = tuple[str, str, Permission, dict[str, Any] | None, dict[str, str] | None]
CASES: list[Case] = [
    ("GET", "/api/v1/meta/version", Permission.meta_read, None, None),
    ("GET", "/api/v1/auth/me", Permission.auth_self, None, None),
    ("POST", "/api/v1/auth/logout", Permission.auth_self, None, None),
    ("GET", "/api/v1/assets", Permission.assets_read, None, None),
    ("GET", "/api/v1/assets/resolve", Permission.assets_read, None, {"ip": "10.0.0.1"}),
    ("GET", f"/api/v1/assets/{ZERO}", Permission.assets_read, None, None),
    ("POST", "/api/v1/assets", Permission.assets_write, ASSET, None),
    ("PATCH", f"/api/v1/assets/{ZERO}", Permission.assets_write, {"owner": "x"}, None),
    ("POST", "/api/v1/assets/bulk", Permission.assets_admin, BULK, None),
    ("DELETE", f"/api/v1/assets/{ZERO}", Permission.assets_admin, None, None),
    ("GET", "/api/v1/events", Permission.events_read, None, WINDOW),
    ("GET", "/api/v1/events/stats", Permission.events_read, None, WINDOW),
    ("GET", f"/api/v1/events/{ZERO}", Permission.events_payload, None, None),
    ("GET", "/api/v1/ingest/batches", Permission.ingest_read, None, None),
    ("GET", f"/api/v1/ingest/batches/{ZERO}", Permission.ingest_read, None, None),
    ("GET", f"/api/v1/ingest/batches/{ZERO}/rejects", Permission.ingest_read, None, None),
    (
        "POST",
        "/api/v1/ingest/eve",
        Permission.ingest_write,
        None,
        {"source_label": "rbac", "mode": "sync"},
    ),
    (
        "POST",
        "/api/v1/ingest/import",
        Permission.ingest_import,
        {"dataset_id": "nope", "source_label": "rbac"},
        None,
    ),
    ("GET", "/api/v1/audit", Permission.audit_read, None, None),
    ("GET", "/api/v1/alerts", Permission.alerts_read, None, None),
    ("GET", f"/api/v1/alerts/{ZERO}", Permission.alerts_read, None, None),
    ("GET", "/api/v1/detections/rules", Permission.alerts_read, None, None),
    ("GET", "/api/v1/detections/runs", Permission.detections_read, None, None),
    ("GET", "/api/v1/detections/baselines", Permission.detections_read, None, None),
    (
        "POST",
        "/api/v1/detections/baselines/recompute",
        Permission.detections_run,
        {"window_days": 7},
        None,
    ),
    (
        "POST",
        "/api/v1/detections/sweeps",
        Permission.detections_run,
        {"from": "2026-09-01T00:00:00Z", "to": "2026-09-01T01:00:00Z"},
        None,
    ),
    ("GET", "/api/v1/incidents", Permission.incidents_read, None, None),
    ("GET", f"/api/v1/incidents/{ZERO}", Permission.incidents_read, None, None),
    ("GET", f"/api/v1/incidents/{ZERO}/timeline", Permission.incidents_read, None, None),
    ("GET", f"/api/v1/incidents/{ZERO}/notes", Permission.incidents_read, None, None),
    (
        "POST",
        f"/api/v1/incidents/{ZERO}/status",
        Permission.incidents_write,
        {"status": "triaging"},
        None,
    ),
    (
        "POST",
        f"/api/v1/incidents/{ZERO}/notes",
        Permission.incidents_write,
        {"body": "looked at this"},
        None,
    ),
]
ROLES = ["viewer", "analyst", "admin", "ingest_service"]


def _api_routes(app: FastAPI) -> list[APIRoute]:
    """Every APIRoute, however deeply the routers are included."""
    found: list[APIRoute] = []
    stack: list[Any] = list(app.routes)
    while stack:
        route = stack.pop()
        if isinstance(route, APIRoute):
            found.append(route)
        else:  # FastAPI >= 0.141 wraps an included router; older versions inline its routes
            inner = getattr(route, "original_router", route)
            stack.extend(getattr(inner, "routes", []))
    return found


def _permission_of(route: APIRoute) -> Permission | None:
    stack = list(route.dependant.dependencies)
    while stack:
        dependant = stack.pop()
        marker = getattr(dependant.call, "aegisnet_permission", None)
        if marker is not None:
            assert isinstance(marker, Permission)
            return marker
        stack.extend(dependant.dependencies)
    return None


def test_every_route_declares_a_permission_or_is_on_the_public_allowlist(app: FastAPI) -> None:
    public: set[tuple[str, str]] = set()
    guarded: set[tuple[str, str]] = set()
    for route in _api_routes(app):
        for method in route.methods:
            (public if _permission_of(route) is None else guarded).add((method, route.path))
    assert public == PUBLIC_ROUTES
    assert len(guarded) >= len(CASES)
    assert not any(path.startswith("/api/") and method == "OPTIONS" for method, path in guarded)


def test_every_matrix_case_hits_a_route_with_the_permission_it_claims(app: FastAPI) -> None:
    by_route = {
        (method, route.path): _permission_of(route)
        for route in _api_routes(app)
        for method in route.methods
    }
    for method, path, permission, _body, _params in CASES:
        template = path.replace(str(ZERO), "{asset_id}")
        candidates = {
            by_route.get((method, template.replace("{asset_id}", placeholder)))
            for placeholder in (
                "{asset_id}",
                "{event_id}",
                "{batch_id}",
                "{alert_id}",
                "{incident_id}",
            )
        }
        assert permission in candidates, (method, path)


@pytest.fixture(params=ROLES)
async def role_headers(
    request: pytest.FixtureRequest, wiring: FakeWiring
) -> tuple[str, dict[str, str]]:
    role: str = request.param
    if role == "ingest_service":
        return role, await wiring.service_token_headers()
    email = f"{role}@example.test"
    await wiring.add_user(email, UserRole(role))
    return role, await wiring.login_headers(email)


@pytest.mark.parametrize("case", CASES, ids=[f"{m} {p}" for m, p, *_ in CASES])
def test_the_matrix_holds_for_every_role(
    client: TestClient,
    wiring: FakeWiring,
    role_headers: tuple[str, dict[str, str]],
    case: Case,
) -> None:
    role, headers = role_headers
    method, path, permission, body, params = case
    response = client.request(method, path, json=body, params=params, headers=headers)
    if permission in ROLE_PERMISSIONS[role]:
        assert response.status_code not in (401, 403), response.text
        assert "rbac.denied" not in wiring.audit_actions()
    else:
        assert response.status_code == 403, response.text
        assert response.json()["error"]["code"] == "forbidden"
        entry = wiring.audit_store.entries[-1]
        assert entry.action == "rbac.denied" and entry.target_id == f"{method} {path}"
        assert entry.detail == {"permission": permission.value, "role": role}
        assert (entry.actor_user_id is None) == (role == "ingest_service")


def test_missing_or_malformed_credentials_are_401_never_anonymous(
    client: TestClient, wiring: FakeWiring
) -> None:
    attempts: list[dict[str, str]] = [
        {},
        {"Authorization": "Bearer "},
        {"Authorization": "Basic YWJjOmRlZg=="},
        {"Authorization": "Bearer not.a.jwt"},
        {"Authorization": "Token abc"},
        {"X-Ingest-Token": "nope"},
    ]
    for headers in attempts:
        response = client.get("/api/v1/meta/version", headers=headers)
        assert response.status_code == 401, headers
        assert response.headers["www-authenticate"] == "Bearer"
        assert response.json()["error"]["code"] == "unauthenticated"
    assert wiring.audit_actions() == []


def test_a_service_token_is_not_a_user(client: TestClient, service_headers: dict[str, str]) -> None:
    assert client.get("/api/v1/auth/me", headers=service_headers).status_code == 403
    assert client.get("/api/v1/ingest/batches", headers=service_headers).status_code == 403
    assert client.get("/api/v1/meta/version", headers=service_headers).status_code == 200


def test_permissions_follow_the_stored_role_not_the_token(
    client: TestClient, wiring: FakeWiring, analyst_headers: dict[str, str]
) -> None:
    assert client.get("/api/v1/assets", headers=analyst_headers).status_code == 200
    user = next(iter(wiring.users.rows.values()))
    wiring.users.rows[user.id] = dataclasses.replace(user, role=UserRole.viewer)
    assert client.get("/api/v1/assets", headers=analyst_headers).status_code == 401
