"""Login, refresh, logout, me over HTTP: cookies, rotation, reuse, limits, audit."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from aegisnet.domain.enums import UserRole
from aegisnet.domain.ports import UserRecord
from aegisnet.main import create_app
from tests.conftest import PASSWORD, TEST_SECRET_KEY, make_settings
from tests.fakes import FakeWiring

pytestmark = pytest.mark.integration

LOGIN = "/api/v1/auth/login"
REFRESH = "/api/v1/auth/refresh"
LOGOUT = "/api/v1/auth/logout"
ME = "/api/v1/auth/me"
EMAIL = "ana@example.test"
COOKIE = "aegisnet_refresh"


@pytest.fixture
async def ana(wiring: FakeWiring) -> UserRecord:
    return await wiring.add_user(EMAIL, UserRole.analyst)


def _login(client: TestClient, email: str = EMAIL, password: str = PASSWORD) -> httpx.Response:
    return client.post(LOGIN, json={"email": email, "password": password})


def _bearer(response: httpx.Response) -> dict[str, str]:
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def test_login_returns_a_bearer_and_a_hardened_refresh_cookie(
    client: TestClient, wiring: FakeWiring, ana: UserRecord
) -> None:
    response = _login(client, email="Ana@Example.test")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["token_type"] == "bearer"
    assert body["expires_in"] == wiring.settings.access_ttl_seconds
    cookie = response.headers["set-cookie"].lower()
    assert cookie.startswith(f"{COOKIE}=") and "httponly" in cookie
    assert "samesite=strict" in cookie and "path=/api/v1/auth" in cookie
    assert "secure" not in cookie  # cookie_secure=False in the test settings only
    me = client.get(ME, headers=_bearer(response))
    assert me.status_code == 200
    assert me.json()["email"] == EMAIL and me.json()["role"] == "analyst"
    assert me.json()["id"] == str(ana.id)
    assert wiring.audit_actions() == ["auth.login_success"]
    assert wiring.audit_store.entries[0].actor_user_id == ana.id


async def test_the_refresh_cookie_is_secure_by_default(tmp_path: Path) -> None:
    settings = make_settings(spool_dir=tmp_path / "spool", secret_key=TEST_SECRET_KEY)
    assert settings.cookie_secure is True
    wiring = FakeWiring(settings, tmp_path / "spool")
    await wiring.add_user(EMAIL, UserRole.viewer)
    app = create_app(settings, services_factory=wiring.factory())
    with TestClient(app) as client:
        response = _login(client)
    assert response.status_code == 200
    assert "; secure" in response.headers["set-cookie"].lower()


def test_wrong_password_and_unknown_user_look_the_same(
    client: TestClient, wiring: FakeWiring, ana: UserRecord
) -> None:
    wrong = _login(client, password="not the password")
    unknown = _login(client, email="nobody@example.test", password="not the password")
    for response in (wrong, unknown):
        assert response.status_code == 401
        assert response.json()["error"]["code"] == "invalid_credentials"
        assert "set-cookie" not in response.headers
    assert wrong.json()["error"]["message"] == unknown.json()["error"]["message"]
    assert wiring.audit_actions() == ["auth.login_failed", "auth.login_failed"]
    first, second = wiring.audit_store.entries
    assert first.detail == {"reason": "wrong_password", "locked": False}
    assert first.target_id == str(ana.id)
    assert second.detail == {"reason": "unknown_user", "locked": False}
    assert second.target_id is None


def test_refresh_rotates_and_a_replayed_cookie_kills_the_chain(
    client: TestClient, wiring: FakeWiring, ana: UserRecord
) -> None:
    first = _login(client)
    old_cookie = first.cookies[COOKIE]
    wiring.clock.advance(timedelta(minutes=5))
    rotated = client.post(REFRESH)  # the client's jar carries the cookie to /api/v1/auth
    assert rotated.status_code == 200, rotated.text
    new_cookie = rotated.cookies[COOKIE]
    assert new_cookie != old_cookie
    assert rotated.json()["access_token"] != first.json()["access_token"]
    assert client.get(ME, headers=_bearer(rotated)).status_code == 200
    client.cookies.clear()
    replay = client.post(REFRESH, headers={"Cookie": f"{COOKIE}={old_cookie}"})
    assert replay.status_code == 401
    assert replay.json()["error"]["code"] == "invalid_credentials"
    cleared = replay.headers["set-cookie"].lower()
    assert cleared.startswith(f"{COOKIE}=") and "max-age=0" in cleared
    assert "auth.refresh_reuse_detected" in wiring.audit_actions()
    dead = client.post(REFRESH, headers={"Cookie": f"{COOKIE}={new_cookie}"})
    assert dead.status_code == 401
    assert client.post(REFRESH).status_code == 401  # no cookie at all
    assert wiring.audit_actions().count("auth.refresh") == 1


def test_logout_denies_the_access_token_and_revokes_the_refresh_chain(
    client: TestClient, wiring: FakeWiring, ana: UserRecord
) -> None:
    login = _login(client)
    headers = _bearer(login)
    assert client.get(ME, headers=headers).status_code == 200
    out = client.post(LOGOUT, headers=headers)
    assert out.status_code == 204 and "max-age=0" in out.headers["set-cookie"].lower()
    assert client.get(ME, headers=headers).status_code == 401
    client.cookies.clear()
    replay = client.post(REFRESH, headers={"Cookie": f"{COOKIE}={login.cookies[COOKIE]}"})
    assert replay.status_code == 401
    assert client.post(LOGOUT).status_code == 401
    entry = next(e for e in wiring.audit_store.entries if e.action == "auth.logout")
    assert entry.actor_user_id == ana.id and entry.detail == {"sessions_revoked": 1}


def test_login_is_rate_limited_per_client_and_fails_closed(
    client: TestClient, wiring: FakeWiring, ana: UserRecord
) -> None:
    limit = wiring.settings.rate_limit_login_per_15min
    for _ in range(limit):
        assert _login(client, password="not the password").status_code == 401
    blocked = _login(client)
    assert blocked.status_code == 429
    assert blocked.json()["error"]["code"] == "rate_limited"
    assert int(blocked.headers["retry-after"]) >= 1
    assert wiring.audit_actions().count("auth.login_failed") == limit
    wiring.clock.advance(timedelta(minutes=16))  # past the window and the account lockout
    assert _login(client).status_code == 200
    wiring.limiter.broken = True
    assert _login(client).status_code == 429


def test_read_routes_fail_open_when_the_limiter_is_down(
    client: TestClient, wiring: FakeWiring, viewer_headers: dict[str, str]
) -> None:
    wiring.limiter.broken = True
    assert client.get("/api/v1/assets", headers=viewer_headers).status_code == 200


@pytest.mark.parametrize(
    "body",
    [
        {"email": EMAIL},
        {"email": EMAIL, "password": PASSWORD, "extra": 1},
        {"email": "a", "password": ""},
        {"email": EMAIL, "password": "x" * 129},
    ],
)
def test_malformed_login_bodies_are_422(client: TestClient, body: dict[str, object]) -> None:
    response = client.post(LOGIN, json=body)
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_failed"


async def test_the_address_budget_and_the_account_budget_are_separate_numbers(
    wiring: FakeWiring, tmp_path: Path
) -> None:
    """One setting fed both until Chunk 28, which meant a deployment behind a NAT could only
    buy itself room by also widening how many guesses an attacker gets at a single account
    (T-2.1, R-9). They are independent now, and this proves it by moving one.

    The shipped defaults are unchanged and equal; what changed is that they *can* differ.
    """
    settings = make_settings(
        cookie_secure=False,
        spool_dir=tmp_path / "spool",
        secret_key=TEST_SECRET_KEY,
        rate_limit_login_ip_per_15min=9,
        rate_limit_login_per_15min=2,
    )
    wiring = FakeWiring(settings, settings.spool_dir)
    await wiring.add_user("ana@example.test", UserRole.analyst, "correct horse battery")

    with TestClient(create_app(settings, services_factory=wiring.factory())) as client:  # type: ignore[arg-type]
        # Two wrong passwords for one account spend that account's budget, and the third is
        # refused by the account limit while the address still has room.
        for _ in range(2):
            assert _login(client, "ana@example.test", "wrong").status_code == 401
        assert _login(client, "ana@example.test", "wrong").status_code == 429

        # A different account from the same address is still served: the address budget is its
        # own number and has not been spent by the account above.
        other = _login(client, "someone-else@example.test", "wrong")
        assert other.status_code == 401, "the account budget was charged to the address"


def test_the_shipped_login_budgets_are_equal_so_nothing_loosened(tmp_path: Path) -> None:
    """Splitting the setting must not have quietly widened anything. The defaults are the same
    number they always were; only the ability to move them apart is new."""
    shipped = make_settings(secret_key=TEST_SECRET_KEY, spool_dir=tmp_path / "spool")
    assert shipped.rate_limit_login_ip_per_15min == shipped.rate_limit_login_per_15min == 5
