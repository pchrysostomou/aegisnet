"""AuthService over in-memory stores: login, lockout, refresh rotation and reuse detection,
logout, and every way an access or service token can be refused."""

from __future__ import annotations

import base64
import dataclasses
import json
from datetime import timedelta
from uuid import UUID, uuid4

import jwt
import pytest

from aegisnet.adapters.db.auth_store import EmailTakenError
from aegisnet.domain.auth import (
    InvalidCredentialsError,
    NotAuthenticatedError,
    PasswordPolicyError,
    PrincipalKind,
    RefreshReuseError,
    hash_token,
)
from aegisnet.domain.enums import ServiceTokenRole, UserRole
from aegisnet.domain.ports import UserRecord
from aegisnet.services.auth_service import (
    CLOCK_SKEW_SECONDS,
    MAX_LOCKOUT_STEP,
    MIN_SECRET_BYTES,
    AuthPolicy,
    AuthService,
    LoginFailure,
    LoginOutcome,
    LoginRejectedError,
)
from tests.fakes import (
    TEST_HASHER,
    Clock,
    FakeDenylist,
    FakeRefreshTokenStore,
    FakeServiceTokenStore,
    FakeUserStore,
)

pytestmark = pytest.mark.unit

SECRET = "unit-test-signing-key-" + "0" * 16
PASSWORD = "correct horse battery"
EMAIL = "ana@example.test"
POLICY = AuthPolicy(
    issuer="aegisnet-test",
    access_ttl=timedelta(minutes=15),
    refresh_ttl=timedelta(days=14),
    max_failures=3,
    lockout=timedelta(minutes=15),
    lockout_ceiling=timedelta(minutes=60),
    failure_reset=timedelta(hours=24),
)


class Harness:
    def __init__(self, policy: AuthPolicy = POLICY) -> None:
        """`policy` is a parameter so a test can bend one number — the curve's ceiling, the
        forgiveness window — without every other test in the file inheriting it."""
        self.clock = Clock()
        self.users = FakeUserStore()
        self.refresh = FakeRefreshTokenStore()
        self.service = FakeServiceTokenStore()
        self.denylist = FakeDenylist()
        self.auth = AuthService(
            self.users,
            self.refresh,
            self.service,
            self.denylist,
            secret=SECRET,
            policy=policy,
            clock=self.clock,
            hasher=TEST_HASHER,
        )

    async def register(self, email: str = EMAIL, role: UserRole = UserRole.analyst) -> UserRecord:
        return await self.auth.register_user(email, "Ana", PASSWORD, role)

    async def login(self, email: str = EMAIL, password: str = PASSWORD) -> LoginOutcome:
        return await self.auth.login(email, password, ip="10.0.0.1", user_agent="pytest")

    async def rejected(self, email: str = EMAIL, password: str = PASSWORD) -> LoginFailure:
        with pytest.raises(LoginRejectedError) as excinfo:
            await self.login(email, password)
        assert str(excinfo.value) == "invalid credentials"
        return excinfo.value.failure

    async def user(self, user_id: UUID) -> UserRecord:
        record = await self.users.get(user_id)
        assert record is not None
        return record

    def replace(self, user_id: UUID, **changes: object) -> None:
        self.users.rows[user_id] = dataclasses.replace(self.users.rows[user_id], **changes)  # type: ignore[arg-type]


@pytest.fixture
def h() -> Harness:
    return Harness()


def _claims(token: str) -> dict[str, object]:
    claims: dict[str, object] = jwt.decode(token, options={"verify_signature": False})
    return claims


def _forge(claims: dict[str, object], key: str = SECRET) -> str:
    return jwt.encode(claims, key, algorithm="HS256")


def test_a_short_signing_secret_is_refused(h: Harness) -> None:
    with pytest.raises(ValueError, match="at least 32"):
        AuthService(
            h.users,
            h.refresh,
            h.service,
            h.denylist,
            secret="x" * (MIN_SECRET_BYTES - 1),
            policy=POLICY,
        )


async def test_register_normalises_the_address_and_enforces_the_policy(h: Harness) -> None:
    user = await h.auth.register_user("  Ana@Example.TEST ", " Ana ", PASSWORD, UserRole.viewer)
    assert user.email == EMAIL and user.display_name == "Ana" and user.role is UserRole.viewer
    assert user.password_hash != PASSWORD and TEST_HASHER.verify(user.password_hash, PASSWORD)
    with pytest.raises(PasswordPolicyError):
        await h.auth.register_user("b@example.test", "B", "short", UserRole.viewer)
    with pytest.raises(ValueError, match="address"):
        await h.auth.register_user("not-an-address", "B", PASSWORD, UserRole.viewer)
    with pytest.raises(EmailTakenError):
        await h.register()


async def test_login_issues_a_bearer_and_a_refresh_token_and_stamps_the_user(h: Harness) -> None:
    user = await h.register()
    outcome = await h.login()
    assert outcome.user.id == user.id and outcome.access_expires_in == 15 * 60
    claims = _claims(outcome.access_token)
    assert claims["iss"] == "aegisnet-test" and claims["sub"] == str(user.id)
    assert claims["role"] == "analyst" and claims["email"] == EMAIL
    assert claims["iat"] == int(h.clock.now.timestamp())
    assert int(str(claims["exp"])) - int(str(claims["iat"])) == 15 * 60
    stored = await h.refresh.get_by_hash(hash_token(outcome.refresh_token))
    assert stored is not None and stored.user_id == user.id
    assert stored.expires_at == outcome.refresh_expires_at == h.clock.now + timedelta(days=14)
    assert all(len(r.token_hash) == 32 for r in h.refresh.rows.values())
    stamped = await h.user(user.id)
    assert stamped.last_login_at == h.clock.now and stamped.failed_login_count == 0


async def test_unknown_users_and_wrong_passwords_look_the_same_to_the_caller(h: Harness) -> None:
    user = await h.register()
    unknown = await h.rejected("nobody@example.test")
    wrong = await h.rejected(password="wrong password here")
    assert unknown.reason == "unknown_user" and unknown.user_id is None
    assert wrong.reason == "wrong_password" and wrong.user_id == user.id and not wrong.locked
    assert (await h.user(user.id)).failed_login_count == 1


async def test_the_account_locks_after_max_failures_and_releases_after_the_window(
    h: Harness,
) -> None:
    user = await h.register()
    for attempt in range(1, POLICY.max_failures + 1):
        failure = await h.rejected(password="wrong password here")
        assert failure.locked is (attempt == POLICY.max_failures)
    locked = await h.rejected()  # the right password is refused while locked
    assert locked.reason == "locked" and locked.locked
    h.clock.advance(POLICY.lockout - timedelta(seconds=1))
    assert (await h.rejected()).reason == "locked"
    h.clock.advance(timedelta(seconds=2))
    assert (await h.login()).user.id == user.id
    released = await h.user(user.id)
    assert released.failed_login_count == 0 and released.locked_until is None


async def test_deactivated_users_cannot_log_in(h: Harness) -> None:
    user = await h.register()
    h.users.deactivate(user.id)
    assert (await h.rejected()).reason == "inactive"


async def test_refresh_rotates_the_token_and_reuse_revokes_the_whole_chain(h: Harness) -> None:
    await h.register()
    first = await h.login()
    h.clock.advance(timedelta(minutes=1))
    second = await h.auth.refresh(first.refresh_token, ip=None, user_agent=None)
    assert second.refresh_token != first.refresh_token
    assert second.access_token != first.access_token
    old = await h.refresh.get_by_hash(hash_token(first.refresh_token))
    new = await h.refresh.get_by_hash(hash_token(second.refresh_token))
    assert old is not None and new is not None
    assert old.rotated_to == new.id and old.revoked_at == h.clock.now and new.revoked_at is None
    with pytest.raises(RefreshReuseError):
        await h.auth.refresh(first.refresh_token, ip=None, user_agent=None)
    new = await h.refresh.get_by_hash(hash_token(second.refresh_token))
    assert new is not None and new.revoked_at is not None  # the descendant died with the reuse
    with pytest.raises(RefreshReuseError):
        await h.auth.refresh(second.refresh_token, ip=None, user_agent=None)
    with pytest.raises(InvalidCredentialsError):
        await h.auth.refresh("not-a-token", ip=None, user_agent=None)


async def test_expired_refresh_tokens_and_deactivated_users_are_refused(h: Harness) -> None:
    user = await h.register()
    outcome = await h.login()
    h.clock.advance(POLICY.refresh_ttl)
    with pytest.raises(InvalidCredentialsError, match="expired"):
        await h.auth.refresh(outcome.refresh_token, ip=None, user_agent=None)
    h.clock.advance(-POLICY.refresh_ttl)
    h.users.deactivate(user.id)
    with pytest.raises(InvalidCredentialsError):
        await h.auth.refresh(outcome.refresh_token, ip=None, user_agent=None)


async def test_logout_revokes_the_chain_and_denies_the_access_token(h: Harness) -> None:
    await h.register()
    outcome = await h.login()
    principal = await h.auth.authenticate_access(outcome.access_token)
    assert principal.kind is PrincipalKind.user
    assert principal.token_id == _claims(outcome.access_token)["jti"]
    assert await h.auth.logout(outcome.refresh_token, principal) == 1
    with pytest.raises(NotAuthenticatedError, match="revoked"):
        await h.auth.authenticate_access(outcome.access_token)
    with pytest.raises(RefreshReuseError):
        await h.auth.refresh(outcome.refresh_token, ip=None, user_agent=None)
    assert await h.auth.logout(None, None) == 0
    assert await h.auth.logout("unknown", None) == 0


async def test_access_tokens_expire_by_the_service_clock_within_a_bounded_skew(
    h: Harness,
) -> None:
    await h.register()
    token = (await h.login()).access_token
    h.clock.advance(POLICY.access_ttl + timedelta(seconds=CLOCK_SKEW_SECONDS - 1))
    await h.auth.authenticate_access(token)
    h.clock.advance(timedelta(seconds=1))
    with pytest.raises(NotAuthenticatedError, match="expired"):
        await h.auth.authenticate_access(token)


async def test_forged_tampered_and_malformed_access_tokens_are_refused(h: Harness) -> None:
    user = await h.register()
    now = int(h.clock.now.timestamp())
    base: dict[str, object] = {
        "iss": "aegisnet-test",
        "sub": str(user.id),
        "role": "analyst",
        "iat": now,
        "exp": now + 900,
        "jti": uuid4().hex,
    }
    await h.auth.authenticate_access(_forge(base))  # the well-formed control case
    header, _, signature = _forge(base).partition(".")[0], None, _forge(base).rsplit(".", 1)[1]
    escalated = json.dumps({**base, "role": "admin"}).encode()
    tampered_payload = base64.urlsafe_b64encode(escalated).decode().rstrip("=")
    cases = {
        "tampered payload": f"{header}.{tampered_payload}.{signature}",
        "another key": _forge(base, key="another-key-that-is-also-long-enough-0000"),
        "alg none": jwt.encode(base, key=None, algorithm="none"),
        "wrong issuer": _forge({**base, "iss": "someone-else"}),
        "missing jti": _forge({k: v for k, v in base.items() if k != "jti"}),
        "missing role": _forge({k: v for k, v in base.items() if k != "role"}),
        "missing exp": _forge({k: v for k, v in base.items() if k != "exp"}),
        "bad subject": _forge({**base, "sub": "not-a-uuid"}),
        "unknown role": _forge({**base, "role": "superuser"}),
        "unknown user": _forge({**base, "sub": str(uuid4())}),
        "garbage": "not.a.token",
        "empty": "",
    }
    for label, token in cases.items():
        with pytest.raises(NotAuthenticatedError):
            await h.auth.authenticate_access(token)
        assert label  # keeps the loop readable in failure output
    with pytest.raises(NotAuthenticatedError, match="lifetime"):
        await h.auth.authenticate_access(_forge({**base, "exp": now + 7200}))
    with pytest.raises(NotAuthenticatedError, match="not yet valid"):
        await h.auth.authenticate_access(_forge({**base, "iat": now + 3600, "exp": now + 4500}))


async def test_access_tokens_die_with_role_change_deactivation_or_deletion(h: Harness) -> None:
    user = await h.register()
    token = (await h.login()).access_token
    h.replace(user.id, role=UserRole.viewer)
    with pytest.raises(NotAuthenticatedError):
        await h.auth.authenticate_access(token)
    h.replace(user.id, role=UserRole.analyst)
    await h.auth.authenticate_access(token)
    h.users.deactivate(user.id)
    with pytest.raises(NotAuthenticatedError):
        await h.auth.authenticate_access(token)
    del h.users.rows[user.id]
    with pytest.raises(NotAuthenticatedError):
        await h.auth.authenticate_access(token)


async def test_service_tokens_authenticate_touch_expire_and_revoke(h: Harness) -> None:
    admin = await h.register("root@example.test", UserRole.admin)
    plaintext, record = await h.auth.create_service_token(
        " sensor-a ", created_by=admin.id, ttl=timedelta(days=1)
    )
    assert record.name == "sensor-a" and record.role is ServiceTokenRole.ingest_service
    assert record.created_by == admin.id
    assert record.expires_at == h.clock.now + timedelta(days=1)
    assert record.token_hash == hash_token(plaintext) and plaintext not in repr(record)
    h.clock.advance(timedelta(hours=1))
    principal = await h.auth.authenticate_service_token(plaintext)
    assert principal.kind is PrincipalKind.service_token and principal.id == record.id
    assert principal.role == "ingest_service"
    assert [t.last_used_at for t in await h.auth.list_service_tokens()] == [h.clock.now]
    with pytest.raises(NotAuthenticatedError):
        await h.auth.authenticate_service_token("nope")
    h.clock.advance(timedelta(days=1))
    with pytest.raises(NotAuthenticatedError):
        await h.auth.authenticate_service_token(plaintext)  # expired
    other, other_record = await h.auth.create_service_token(
        "sensor-b", created_by=None, ttl=timedelta(days=30)
    )
    revoked = await h.auth.revoke_service_token(other_record.id)
    assert revoked is not None and revoked.revoked_at == h.clock.now
    with pytest.raises(NotAuthenticatedError):
        await h.auth.authenticate_service_token(other)
    assert await h.auth.revoke_service_token(uuid4()) is None
    assert {t.name for t in await h.auth.list_service_tokens()} == {"sensor-a", "sensor-b"}


@pytest.mark.parametrize(
    ("name", "ttl"),
    [
        ("", timedelta(days=1)),
        ("x" * 65, timedelta(days=1)),
        ("ok", timedelta(0)),
        ("ok", timedelta(days=366)),
    ],
)
async def test_service_token_name_and_lifetime_are_bounded(
    h: Harness, name: str, ttl: timedelta
) -> None:
    with pytest.raises(ValueError, match="service token"):
        await h.auth.create_service_token(name, created_by=None, ttl=ttl)


async def test_current_user_requires_an_active_account(h: Harness) -> None:
    user = await h.register()
    principal = await h.auth.authenticate_access((await h.login()).access_token)
    assert (await h.auth.current_user(principal)).id == user.id
    assert [u.id for u in await h.auth.list_users()] == [user.id]
    h.users.deactivate(user.id)
    with pytest.raises(NotAuthenticatedError):
        await h.auth.current_user(principal)


# ---------------------------------------------------------------- the lock lengthens (T-2.1)


async def test_each_lock_is_twice_the_last_until_the_ceiling(h: Harness) -> None:
    """A flat lock is a fixed price an attacker pays per batch of guesses. Doubling it makes the
    next batch cost more without ever becoming a permanent denial of service (T-2.1).

    Driven entirely on the injected clock: nothing here sleeps, and the assertion is on the
    stored `locked_until` rather than on how long a call took.
    """
    user = await h.register()
    wrong = "wrong password here"

    async def lock_again() -> timedelta:
        """One more wrong password past the threshold; returns the lock it produced."""
        started = h.clock.now
        failure = await h.rejected(password=wrong)
        assert failure.locked, "past the threshold every failure locks"
        locked_until = (await h.user(user.id)).locked_until
        assert locked_until is not None
        return locked_until - started

    for _ in range(POLICY.max_failures - 1):
        assert not (await h.rejected(password=wrong)).locked

    assert await lock_again() == timedelta(minutes=15), "the first lock is the configured one"
    h.clock.advance(timedelta(minutes=15))
    assert await lock_again() == timedelta(minutes=30)
    h.clock.advance(timedelta(minutes=30))
    assert await lock_again() == timedelta(minutes=60)
    h.clock.advance(timedelta(minutes=60))
    assert await lock_again() == timedelta(minutes=60), "the ceiling holds"


async def test_a_lock_nobody_touched_for_long_enough_is_forgotten(h: Harness) -> None:
    """Otherwise the escalation is permanent: an account locked once and never successfully
    logged into carries its count for ever, so its owner meets the ceiling on their first typo
    a month later."""
    user = await h.register()
    wrong = "wrong password here"
    for _ in range(POLICY.max_failures):
        await h.rejected(password=wrong)
    assert (await h.user(user.id)).failed_login_count == POLICY.max_failures

    # Long after the lock ended, one wrong password starts the count again rather than
    # escalating — and the stale anchor goes with it, or it would forgive for ever.
    h.clock.advance(POLICY.lockout + POLICY.failure_reset)
    failure = await h.rejected(password=wrong)

    assert not failure.locked, "a forgiven account is one failure in, not at the threshold"
    forgiven = await h.user(user.id)
    assert forgiven.failed_login_count == 1
    assert forgiven.locked_until is None, "the anchor was left behind and would forgive again"

    # And from there the ladder starts at the bottom, not where it left off.
    for _ in range(POLICY.max_failures - 2):
        assert not (await h.rejected(password=wrong)).locked
    started = h.clock.now
    assert (await h.rejected(password=wrong)).locked
    again = await h.user(user.id)
    assert again.locked_until is not None
    assert again.locked_until - started == POLICY.lockout


async def test_a_lock_that_ended_recently_still_escalates(h: Harness) -> None:
    """The other side of the same rule: forgiveness is for an account nobody has touched, not
    for an attacker who waits out each lock and comes back."""
    user = await h.register()
    wrong = "wrong password here"
    for _ in range(POLICY.max_failures):
        await h.rejected(password=wrong)

    h.clock.advance(POLICY.lockout + timedelta(minutes=1))  # the lock ended, recently
    started = h.clock.now
    assert (await h.rejected(password=wrong)).locked
    escalated = await h.user(user.id)
    assert escalated.locked_until is not None
    assert escalated.locked_until - started == timedelta(minutes=30), "it did not escalate"


async def test_a_successful_login_still_puts_the_ladder_back_to_the_bottom(h: Harness) -> None:
    user = await h.register()
    wrong = "wrong password here"
    for _ in range(POLICY.max_failures):
        await h.rejected(password=wrong)
    h.clock.advance(POLICY.lockout + timedelta(seconds=1))
    await h.login()

    for _ in range(POLICY.max_failures - 1):
        assert not (await h.rejected(password=wrong)).locked
    started = h.clock.now
    assert (await h.rejected(password=wrong)).locked
    fresh = await h.user(user.id)
    assert fresh.locked_until is not None
    assert fresh.locked_until - started == POLICY.lockout


async def test_a_longer_lock_changes_nothing_the_caller_can_see(h: Harness) -> None:
    """The generic-failure property has to survive the curve. An attacker must not be able to
    read the escalation off the response, or the lock becomes an oracle for which accounts are
    real and how hard somebody has been trying (T-2.1, T-2.4)."""
    await h.register()
    wrong = "wrong password here"
    for _ in range(POLICY.max_failures + 3):
        await h.rejected(password=wrong)

    deep = await h.rejected(password=wrong)
    unknown = await h.rejected(email="nobody@example.test", password=wrong)

    assert deep.reason == "locked" and unknown.reason == "unknown_user"
    # The reason is for the audit log and never leaves the service; what a caller sees is the
    # route's identical 401, which `tests/integration/test_auth_routes.py` pins.
    assert deep.user_id is not None and unknown.user_id is None


def test_the_curve_is_bounded_even_for_a_counter_an_attacker_drives(h: Harness) -> None:
    """`2 ** step` on an unbounded counter is a big-integer computation before it is a long
    lock. The shift is capped, and the ceiling is what actually decides the answer."""
    assert h.auth._lockout_for(POLICY.max_failures) == POLICY.lockout
    assert h.auth._lockout_for(10**6) == POLICY.lockout_ceiling
    assert h.auth._lockout_for(POLICY.max_failures + MAX_LOCKOUT_STEP + 5) == POLICY.lockout_ceiling
