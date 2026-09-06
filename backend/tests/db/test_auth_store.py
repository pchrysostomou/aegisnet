"""The SQL user, refresh-token and service-token stores against PostgreSQL 16, and the
auth service running end to end on them."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from aegisnet.adapters.db.auth_store import (
    EmailTakenError,
    ServiceTokenNameTakenError,
    SqlRefreshTokenStore,
    SqlServiceTokenStore,
    SqlUserStore,
)
from aegisnet.adapters.db.session import make_session_factory
from aegisnet.domain.auth import RefreshReuseError, generate_token, hash_token
from aegisnet.domain.enums import ServiceTokenRole, UserRole
from aegisnet.services.auth_service import AuthPolicy, AuthService
from tests.fakes import TEST_HASHER, Clock, FakeDenylist

pytestmark = [pytest.mark.db, pytest.mark.integration]

T0 = datetime(2026, 9, 5, 12, 0, tzinfo=UTC)
Stores = tuple[SqlUserStore, SqlRefreshTokenStore, SqlServiceTokenStore]


@pytest.fixture(autouse=True)
async def clean_tables(migrator_engine: AsyncEngine) -> AsyncIterator[None]:
    """The app role holds no DELETE, so the owner clears the auth tables between tests."""
    async with migrator_engine.begin() as connection:
        for table in ("refresh_tokens", "audit_log", "service_tokens", "users"):
            await connection.execute(text(f"DELETE FROM {table}"))  # noqa: S608 - fixed names
    yield


@pytest.fixture
def stores(app_engine: AsyncEngine) -> Stores:
    sessions = make_session_factory(app_engine)
    return SqlUserStore(sessions), SqlRefreshTokenStore(sessions), SqlServiceTokenStore(sessions)


async def test_users_are_unique_by_email_and_track_failures_and_locks(stores: Stores) -> None:
    users, _, _ = stores
    user = await users.create("ana@example.test", "Ana", "$argon2id$x", UserRole.analyst, T0)
    assert user.role is UserRole.analyst and user.is_active and user.failed_login_count == 0
    assert await users.get(user.id) == user
    assert await users.get_by_email("ana@example.test") == user
    assert await users.get_by_email("nobody@example.test") is None
    assert await users.get(uuid4()) is None
    with pytest.raises(EmailTakenError):
        await users.create("ana@example.test", "Dup", "$argon2id$y", UserRole.viewer, T0)
    await users.record_failure(user.id, T0, lock_until=None)
    await users.record_failure(user.id, T0, lock_until=T0 + timedelta(minutes=15))
    locked = await users.get(user.id)
    assert locked is not None and locked.failed_login_count == 2
    assert locked.locked_until == T0 + timedelta(minutes=15)
    await users.record_success(user.id, T0 + timedelta(hours=1))
    cleared = await users.get(user.id)
    assert cleared is not None and cleared.failed_login_count == 0
    assert cleared.locked_until is None and cleared.last_login_at == T0 + timedelta(hours=1)
    await users.create("bob@example.test", "Bob", "$argon2id$z", UserRole.viewer, T0 + timedelta(1))
    assert [u.email for u in await users.list()] == ["ana@example.test", "bob@example.test"]


async def test_refresh_tokens_rotate_and_revoke_as_a_chain(stores: Stores) -> None:
    users, refresh, _ = stores
    user = await users.create("ana@example.test", "Ana", "$argon2id$x", UserRole.analyst, T0)
    hashes = [hash_token(generate_token()[0]) for _ in range(3)]
    expires = T0 + timedelta(days=14)
    first = await refresh.create(user.id, hashes[0], T0, expires, b"\x01" * 32, None)
    second = await refresh.create(
        user.id, hashes[1], T0 + timedelta(1), expires, None, b"\x02" * 32
    )
    third = await refresh.create(user.id, hashes[2], T0 + timedelta(2), expires, None, None)
    assert await refresh.get_by_hash(hashes[0]) == first
    assert await refresh.get_by_hash(b"\x00" * 32) is None
    assert first.rotated_to is None and first.revoked_at is None
    await refresh.rotate(first.id, second.id, T0 + timedelta(minutes=1))
    await refresh.rotate(second.id, third.id, T0 + timedelta(minutes=2))
    rotated = await refresh.get_by_hash(hashes[0])
    assert rotated is not None and rotated.rotated_to == second.id
    assert rotated.revoked_at == T0 + timedelta(minutes=1)
    # revoking from the head of the chain reaches the one still-live descendant
    assert await refresh.revoke_chain(first.id, T0 + timedelta(minutes=3)) == 1
    tail = await refresh.get_by_hash(hashes[2])
    assert tail is not None and tail.revoked_at == T0 + timedelta(minutes=3)
    assert await refresh.revoke_chain(first.id, T0 + timedelta(minutes=4)) == 0
    assert await refresh.revoke_chain(uuid4(), T0) == 0


async def test_service_tokens_are_unique_by_name_and_track_use_and_revocation(
    stores: Stores,
) -> None:
    users, _, service = stores
    admin = await users.create("root@example.test", "Root", "$argon2id$x", UserRole.admin, T0)
    plaintext, digest = generate_token()
    role = ServiceTokenRole.ingest_service
    token = await service.create("sensor-a", digest, role, admin.id, T0 + timedelta(days=30), T0)
    assert token.role is role and token.created_by == admin.id and token.last_used_at is None
    assert await service.get_by_hash(digest) == token
    assert await service.get_by_hash(hash_token("nope")) is None
    with pytest.raises(ServiceTokenNameTakenError):
        await service.create("sensor-a", generate_token()[1], role, None, T0 + timedelta(1), T0)
    await service.touch(token.id, T0 + timedelta(hours=1))
    touched = await service.get_by_hash(digest)
    assert touched is not None and touched.last_used_at == T0 + timedelta(hours=1)
    revoked = await service.revoke(token.id, T0 + timedelta(hours=2))
    assert revoked is not None and revoked.revoked_at == T0 + timedelta(hours=2)
    again = await service.revoke(token.id, T0 + timedelta(hours=3))
    assert again is not None and again.revoked_at == T0 + timedelta(hours=2)  # first wins
    assert await service.revoke(uuid4(), T0) is None
    await service.create(
        "sensor-b", generate_token()[1], role, None, T0 + timedelta(1), T0 + timedelta(seconds=1)
    )
    listed = await service.list()
    assert [t.name for t in listed] == ["sensor-a", "sensor-b"]
    assert plaintext not in repr(listed)


async def test_the_auth_service_runs_end_to_end_on_the_sql_stores(stores: Stores) -> None:
    users, refresh, service = stores
    clock = Clock(T0)
    auth = AuthService(
        users,
        refresh,
        service,
        FakeDenylist(),
        secret="db-suite-signing-key-" + "0" * 16,
        policy=AuthPolicy(
            issuer="aegisnet",
            access_ttl=timedelta(minutes=15),
            refresh_ttl=timedelta(days=14),
            max_failures=5,
            lockout=timedelta(minutes=15),
            lockout_ceiling=timedelta(minutes=60),
            failure_reset=timedelta(hours=24),
        ),
        clock=clock,
        hasher=TEST_HASHER,
    )
    user = await auth.register_user(
        "root@example.test", "Root", "correct horse battery", UserRole.admin
    )
    outcome = await auth.login(
        "root@example.test", "correct horse battery", ip="10.0.0.1", user_agent="db-suite"
    )
    principal = await auth.authenticate_access(outcome.access_token)
    assert principal.id == user.id and principal.role == "admin"
    clock.advance(timedelta(minutes=1))
    rotated = await auth.refresh(outcome.refresh_token, ip=None, user_agent=None)
    assert rotated.refresh_token != outcome.refresh_token
    with pytest.raises(RefreshReuseError):
        await auth.refresh(outcome.refresh_token, ip=None, user_agent=None)
    with pytest.raises(RefreshReuseError):  # the whole chain died with the replay
        await auth.refresh(rotated.refresh_token, ip=None, user_agent=None)
    plaintext, record = await auth.create_service_token(
        "sensor-db", created_by=user.id, ttl=timedelta(days=1)
    )
    assert (await auth.authenticate_service_token(plaintext)).id == record.id
