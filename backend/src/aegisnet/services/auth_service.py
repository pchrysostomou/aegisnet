"""Authentication use-cases (FR-10.1, T-2.1, T-2.4).

- Passwords: Argon2id via ``argon2-cffi`` with the library's current defaults; verification
  always runs a hash comparison, even for an unknown e-mail, so timing does not reveal
  whether an account exists.
- Login failures are generic. Wrong password, unknown user, inactive account and a locked
  account all raise :class:`InvalidCredentialsError`; the *audit* entry records which, the
  response never does. After ``login_max_failures`` failures the account locks for
  ``login_lockout_minutes``; the lock is rechecked on every attempt.
- Access tokens are short-lived HS256 JWTs signed with ``SECRET_KEY``, carrying ``sub``,
  ``role``, ``iss``, ``iat``, ``exp`` and a ``jti``. Logout puts the ``jti`` on a denylist
  for the token's remaining life, so a stolen access token dies with the session.
- Refresh tokens are opaque, stored only as sha256, rotated on every use. Presenting a
  rotated token again is treated as theft: the whole chain is revoked
  (:class:`RefreshReuseError`).
- Service tokens (``X-Ingest-Token``) are opaque, stored as sha256, expiring, revocable;
  the plaintext is returned exactly once at creation.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Final

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, VerifyMismatchError

from aegisnet.config import Settings
from aegisnet.domain.auth import (
    InvalidCredentialsError,
    NotAuthenticatedError,
    Principal,
    RefreshReuseError,
    check_password_policy,
    fingerprint,
    generate_token,
    hash_token,
    principal_for_service_token,
    principal_for_user,
)
from aegisnet.domain.enums import ServiceTokenRole, UserRole
from aegisnet.domain.ports import (
    RefreshTokenStore,
    ServiceTokenRecord,
    ServiceTokenStore,
    TokenDenylist,
    UserRecord,
    UserStore,
)
from aegisnet.logging import get_logger

logger = get_logger(__name__)

# Hashing an unknown user's attempt against this keeps the timing of "no such user"
# indistinguishable from "wrong password".
_DUMMY_PASSWORD = "aegisnet-timing-equaliser-not-a-real-password"  # noqa: S105 - not a credential


MIN_SECRET_BYTES = 32
CLOCK_SKEW_SECONDS: Final = 30
"""HS256 needs a key at least as long as its output; PyJWT refuses shorter ones."""


def utc_now() -> datetime:
    return datetime.now(tz=UTC)


@dataclass(frozen=True, slots=True)
class AuthPolicy:
    issuer: str
    access_ttl: timedelta
    refresh_ttl: timedelta
    max_failures: int
    lockout: timedelta

    @classmethod
    def from_settings(cls, settings: Settings) -> AuthPolicy:
        return cls(
            issuer=settings.jwt_issuer,
            access_ttl=timedelta(seconds=settings.access_ttl_seconds),
            refresh_ttl=timedelta(days=settings.refresh_ttl_days),
            max_failures=settings.login_max_failures,
            lockout=timedelta(minutes=settings.login_lockout_minutes),
        )


@dataclass(frozen=True, slots=True)
class LoginOutcome:
    """What a successful login or refresh yields. ``refresh_token`` is plaintext, shown once."""

    user: UserRecord
    access_token: str
    access_expires_in: int
    refresh_token: str
    refresh_expires_at: datetime


@dataclass(frozen=True, slots=True)
class LoginFailure:
    """Which generic failure happened. For the audit trail only; never for the response."""

    reason: str
    user_id: uuid.UUID | None = None
    locked: bool = False


class LoginRejectedError(InvalidCredentialsError):
    """The generic 401, carrying the audit-only reason for the caller that logs it."""

    def __init__(self, failure: LoginFailure) -> None:
        self.failure = failure
        super().__init__("invalid credentials")


class AuthService:
    def __init__(
        self,
        users: UserStore,
        refresh_tokens: RefreshTokenStore,
        service_tokens: ServiceTokenStore,
        denylist: TokenDenylist,
        *,
        secret: str,
        policy: AuthPolicy,
        clock: Callable[[], datetime] = utc_now,
        hasher: PasswordHasher | None = None,
    ) -> None:
        if len(secret.encode("utf-8")) < MIN_SECRET_BYTES:
            raise ValueError(f"SECRET_KEY must be at least {MIN_SECRET_BYTES} bytes")
        self._users = users
        self._refresh = refresh_tokens
        self._service = service_tokens
        self._denylist = denylist
        self._secret = secret
        self._policy = policy
        self._clock = clock
        self._hasher = hasher or PasswordHasher()

    # ---------------------------------------------------------------- users
    async def register_user(
        self, email: str, display_name: str, password: str, role: UserRole
    ) -> UserRecord:
        check_password_policy(password)
        normalised = email.strip().lower()
        if "@" not in normalised or len(normalised) > 254:
            raise ValueError("email must be an address")
        return await self._users.create(
            normalised, display_name.strip(), self._hasher.hash(password), role, self._clock()
        )

    async def login(
        self, email: str, password: str, *, ip: str | None, user_agent: str | None
    ) -> LoginOutcome:
        outcome, failure = await self._attempt(email.strip().lower(), password, ip, user_agent)
        if outcome is None:
            assert failure is not None
            raise LoginRejectedError(failure)
        return outcome

    async def _attempt(
        self, email: str, password: str, ip: str | None, user_agent: str | None
    ) -> tuple[LoginOutcome | None, LoginFailure | None]:
        now = self._clock()
        user = await self._users.get_by_email(email)
        if user is None:
            self._verify(self._hasher.hash(_DUMMY_PASSWORD), password)
            return None, LoginFailure("unknown_user")
        if not user.is_active:
            self._verify(user.password_hash, password)
            return None, LoginFailure("inactive", user.id)
        if user.locked_until is not None and user.locked_until > now:
            self._verify(user.password_hash, password)
            return None, LoginFailure("locked", user.id, locked=True)
        if not self._verify(user.password_hash, password):
            failures = user.failed_login_count + 1
            lock_until = (
                now + self._policy.lockout if failures >= self._policy.max_failures else None
            )
            await self._users.record_failure(user.id, now, lock_until=lock_until)
            return None, LoginFailure("wrong_password", user.id, locked=lock_until is not None)
        await self._users.record_success(user.id, now)
        return await self._issue(user, now, ip, user_agent), None

    def _verify(self, password_hash: str, password: str) -> bool:
        try:
            return bool(self._hasher.verify(password_hash, password))
        except (VerifyMismatchError, VerificationError):
            return False

    # ---------------------------------------------------------------- tokens
    async def _issue(
        self, user: UserRecord, now: datetime, ip: str | None, user_agent: str | None
    ) -> LoginOutcome:
        plaintext, digest = generate_token()
        expires_at = now + self._policy.refresh_ttl
        await self._refresh.create(
            user.id, digest, now, expires_at, fingerprint(user_agent), fingerprint(ip)
        )
        access, ttl = self._mint_access(user, now)
        return LoginOutcome(user, access, ttl, plaintext, expires_at)

    def _mint_access(self, user: UserRecord, now: datetime) -> tuple[str, int]:
        expires = now + self._policy.access_ttl
        claims = {
            "iss": self._policy.issuer,
            "sub": str(user.id),
            "role": user.role.value,
            "email": user.email,
            "iat": int(now.timestamp()),
            "exp": int(expires.timestamp()),
            "jti": uuid.uuid4().hex,
        }
        return jwt.encode(claims, self._secret, algorithm="HS256"), int(
            self._policy.access_ttl.total_seconds()
        )

    async def refresh(
        self, refresh_token: str, *, ip: str | None, user_agent: str | None
    ) -> LoginOutcome:
        now = self._clock()
        record = await self._refresh.get_by_hash(hash_token(refresh_token))
        if record is None:
            raise InvalidCredentialsError("invalid refresh token")
        if record.revoked_at is not None or record.rotated_to is not None:
            revoked = await self._refresh.revoke_chain(record.id, now)
            logger.warning(
                "refresh_token_reuse",
                extra={"user_id": str(record.user_id), "revoked": revoked},
            )
            raise RefreshReuseError("refresh token reuse detected")
        if record.expires_at <= now:
            raise InvalidCredentialsError("refresh token expired")
        user = await self._users.get(record.user_id)
        if user is None or not user.is_active:
            raise InvalidCredentialsError("invalid refresh token")
        outcome = await self._issue(user, now, ip, user_agent)
        new = await self._refresh.get_by_hash(hash_token(outcome.refresh_token))
        assert new is not None
        await self._refresh.rotate(record.id, new.id, now)
        return outcome

    async def logout(self, refresh_token: str | None, principal: Principal | None) -> int:
        """Revoke the presented refresh chain and deny the current access token."""
        now = self._clock()
        revoked = 0
        if refresh_token:
            record = await self._refresh.get_by_hash(hash_token(refresh_token))
            if record is not None:
                revoked = await self._refresh.revoke_chain(record.id, now)
        if principal is not None and principal.token_id is not None:
            await self._denylist.add(
                principal.token_id, int(self._policy.access_ttl.total_seconds())
            )
        return revoked

    async def authenticate_access(self, token: str) -> Principal:
        """Verify an access token: signature, issuer, required claims, lifetime, denylist.

        ``exp`` and ``iat`` are checked against the injected clock (not the wall clock
        PyJWT would use) so the lifetime rules are testable and a skewed host cannot
        extend a token; ``CLOCK_SKEW`` is the only tolerance.
        """
        now = self._clock()
        try:
            claims = jwt.decode(
                token,
                self._secret,
                algorithms=["HS256"],
                issuer=self._policy.issuer,
                options={
                    "require": ["exp", "iat", "sub", "jti", "role"],
                    "verify_exp": False,
                    "verify_iat": False,
                },
            )
        except jwt.PyJWTError as error:
            raise NotAuthenticatedError("invalid access token") from error
        try:
            user_id = uuid.UUID(str(claims["sub"]))
            role = UserRole(str(claims["role"]))
            issued = int(claims["iat"])
            expires = int(claims["exp"])
        except (TypeError, ValueError) as error:
            raise NotAuthenticatedError("invalid access token") from error
        moment = int(now.timestamp())
        if expires <= moment - CLOCK_SKEW_SECONDS:
            raise NotAuthenticatedError("access token expired")
        if issued > moment + CLOCK_SKEW_SECONDS:
            raise NotAuthenticatedError("access token not yet valid")
        if expires - issued > int(self._policy.access_ttl.total_seconds()) + CLOCK_SKEW_SECONDS:
            raise NotAuthenticatedError("access token lifetime exceeds policy")
        jti = str(claims["jti"])
        if await self._denylist.contains(jti):
            raise NotAuthenticatedError("access token revoked")
        user = await self._users.get(user_id)
        if user is None or not user.is_active or user.role is not role:
            raise NotAuthenticatedError("invalid access token")
        return principal_for_user(user.id, user.role, user.email, token_id=jti)

    async def authenticate_service_token(self, token: str) -> Principal:
        now = self._clock()
        record = await self._service.get_by_hash(hash_token(token))
        if record is None or record.revoked_at is not None or record.expires_at <= now:
            raise NotAuthenticatedError("invalid service token")
        await self._service.touch(record.id, now)
        return principal_for_service_token(record.id, record.role)

    async def create_service_token(
        self, name: str, *, created_by: uuid.UUID | None, ttl: timedelta
    ) -> tuple[str, ServiceTokenRecord]:
        if not 1 <= len(name.strip()) <= 64:
            raise ValueError("service token name must be 1 to 64 characters")
        if ttl <= timedelta(0) or ttl > timedelta(days=365):
            raise ValueError("service token lifetime must be between 1 second and 365 days")
        now = self._clock()
        plaintext, digest = generate_token()
        record = await self._service.create(
            name.strip(), digest, ServiceTokenRole.ingest_service, created_by, now + ttl, now
        )
        return plaintext, record

    async def revoke_service_token(self, token_id: uuid.UUID) -> ServiceTokenRecord | None:
        return await self._service.revoke(token_id, self._clock())

    async def list_service_tokens(self) -> tuple[ServiceTokenRecord, ...]:
        return await self._service.list()

    async def list_users(self) -> tuple[UserRecord, ...]:
        return await self._users.list()

    async def current_user(self, principal: Principal) -> UserRecord:
        user = await self._users.get(principal.id)
        if user is None or not user.is_active:
            raise NotAuthenticatedError("invalid access token")
        return user
