"""SQLAlchemy implementations of the user, refresh-token and service-token ports.

All run as the runtime role. Every method is one short transaction. Refresh and service
tokens are looked up by the sha256 of the presented value, so the plaintext never touches
the database or a log line.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from aegisnet.adapters.db.models import RefreshToken, ServiceToken, User
from aegisnet.domain.enums import ServiceTokenRole, UserRole
from aegisnet.domain.ports import RefreshTokenRecord, ServiceTokenRecord, UserRecord


class EmailTakenError(Exception):
    pass


class ServiceTokenNameTakenError(Exception):
    pass


def _user(row: User) -> UserRecord:
    return UserRecord(
        id=row.id,
        email=row.email,
        display_name=row.display_name,
        password_hash=row.password_hash,
        role=UserRole(row.role),
        is_active=row.is_active,
        failed_login_count=row.failed_login_count,
        locked_until=row.locked_until,
        last_login_at=row.last_login_at,
        created_at=row.created_at,
    )


def _refresh(row: RefreshToken) -> RefreshTokenRecord:
    return RefreshTokenRecord(
        id=row.id,
        user_id=row.user_id,
        token_hash=row.token_hash,
        issued_at=row.issued_at,
        expires_at=row.expires_at,
        rotated_to=row.rotated_to,
        revoked_at=row.revoked_at,
    )


def _service(row: ServiceToken) -> ServiceTokenRecord:
    return ServiceTokenRecord(
        id=row.id,
        name=row.name,
        token_hash=row.token_hash,
        role=ServiceTokenRole(row.role),
        created_by=row.created_by,
        expires_at=row.expires_at,
        revoked_at=row.revoked_at,
        last_used_at=row.last_used_at,
        created_at=row.created_at,
    )


class SqlUserStore:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._sessions = session_factory

    async def create(
        self, email: str, display_name: str, password_hash: str, role: UserRole, now: datetime
    ) -> UserRecord:
        async with self._sessions() as session:
            try:
                async with session.begin():
                    row = User(
                        email=email,
                        display_name=display_name,
                        password_hash=password_hash,
                        role=role,
                        is_active=True,
                        failed_login_count=0,
                        created_at=now,
                        updated_at=now,
                    )
                    session.add(row)
                    await session.flush()
                    record = _user(row)
            except IntegrityError as error:
                if "uq_users_email" in str(error.orig):
                    raise EmailTakenError("email already registered") from error
                raise
            return record

    async def get(self, user_id: UUID) -> UserRecord | None:
        async with self._sessions() as session:
            row = await session.get(User, user_id)
            return None if row is None else _user(row)

    async def get_by_email(self, email: str) -> UserRecord | None:
        async with self._sessions() as session:
            row = (
                await session.execute(select(User).where(User.email == email))
            ).scalar_one_or_none()
            return None if row is None else _user(row)

    async def record_failure(
        self, user_id: UUID, now: datetime, *, lock_until: datetime | None
    ) -> None:
        values: dict[str, object] = {
            "failed_login_count": User.failed_login_count + 1,
            "updated_at": now,
        }
        if lock_until is not None:
            values["locked_until"] = lock_until
        async with self._sessions() as session, session.begin():
            await session.execute(update(User).where(User.id == user_id).values(**values))

    async def record_success(self, user_id: UUID, now: datetime) -> None:
        async with self._sessions() as session, session.begin():
            await session.execute(
                update(User)
                .where(User.id == user_id)
                .values(failed_login_count=0, locked_until=None, last_login_at=now, updated_at=now)
            )

    async def list(self) -> tuple[UserRecord, ...]:
        async with self._sessions() as session:
            rows = (
                await session.execute(select(User).order_by(User.created_at, User.id))
            ).scalars()
            return tuple(_user(row) for row in rows)


class SqlRefreshTokenStore:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._sessions = session_factory

    async def create(
        self,
        user_id: UUID,
        token_hash: bytes,
        issued_at: datetime,
        expires_at: datetime,
        user_agent_hash: bytes | None,
        ip_hash: bytes | None,
    ) -> RefreshTokenRecord:
        async with self._sessions() as session, session.begin():
            row = RefreshToken(
                user_id=user_id,
                token_hash=token_hash,
                issued_at=issued_at,
                expires_at=expires_at,
                user_agent_hash=user_agent_hash,
                ip_hash=ip_hash,
            )
            session.add(row)
            await session.flush()
            return _refresh(row)

    async def get_by_hash(self, token_hash: bytes) -> RefreshTokenRecord | None:
        async with self._sessions() as session:
            row = (
                await session.execute(
                    select(RefreshToken).where(RefreshToken.token_hash == token_hash)
                )
            ).scalar_one_or_none()
            return None if row is None else _refresh(row)

    async def rotate(self, old_id: UUID, new_id: UUID, now: datetime) -> None:
        async with self._sessions() as session, session.begin():
            await session.execute(
                update(RefreshToken)
                .where(RefreshToken.id == old_id)
                .values(rotated_to=new_id, revoked_at=now)
            )

    async def revoke_chain(self, token_id: UUID, now: datetime) -> int:
        revoked = 0
        async with self._sessions() as session, session.begin():
            current: UUID | None = token_id
            seen: set[UUID] = set()
            while current is not None and current not in seen:
                seen.add(current)
                row = await session.get(RefreshToken, current)
                if row is None:
                    break
                if row.revoked_at is None:
                    row.revoked_at = now
                    revoked += 1
                current = row.rotated_to
        return revoked


class SqlServiceTokenStore:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._sessions = session_factory

    async def create(
        self,
        name: str,
        token_hash: bytes,
        role: ServiceTokenRole,
        created_by: UUID | None,
        expires_at: datetime,
        now: datetime,
    ) -> ServiceTokenRecord:
        async with self._sessions() as session:
            try:
                async with session.begin():
                    row = ServiceToken(
                        name=name,
                        token_hash=token_hash,
                        role=role,
                        created_by=created_by,
                        expires_at=expires_at,
                        created_at=now,
                    )
                    session.add(row)
                    await session.flush()
                    record = _service(row)
            except IntegrityError as error:
                if "uq_service_tokens_name" in str(error.orig):
                    raise ServiceTokenNameTakenError("service token name already exists") from error
                raise
            return record

    async def get_by_hash(self, token_hash: bytes) -> ServiceTokenRecord | None:
        async with self._sessions() as session:
            row = (
                await session.execute(
                    select(ServiceToken).where(ServiceToken.token_hash == token_hash)
                )
            ).scalar_one_or_none()
            return None if row is None else _service(row)

    async def touch(self, token_id: UUID, now: datetime) -> None:
        async with self._sessions() as session, session.begin():
            await session.execute(
                update(ServiceToken).where(ServiceToken.id == token_id).values(last_used_at=now)
            )

    async def revoke(self, token_id: UUID, now: datetime) -> ServiceTokenRecord | None:
        async with self._sessions() as session, session.begin():
            row = await session.get(ServiceToken, token_id)
            if row is None:
                return None
            if row.revoked_at is None:
                row.revoked_at = now
            await session.flush()
            return _service(row)

    async def list(self) -> tuple[ServiceTokenRecord, ...]:
        async with self._sessions() as session:
            rows = (
                await session.execute(
                    select(ServiceToken).order_by(ServiceToken.created_at, ServiceToken.id)
                )
            ).scalars()
            return tuple(_service(row) for row in rows)
