"""Authentication and authorisation rules (FR-10, T-2.1, T-2.2, T-2.4).

Pure: the permission matrix, what a principal is, the password policy, and how opaque
tokens are generated and hashed. No JWT library, no clock, no I/O; those live in the
auth service and the adapters.

Deny by default. A route declares one permission; a principal holds the permissions of
its role and nothing else; there is no implicit-allow path anywhere.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from enum import StrEnum, unique
from typing import Final
from uuid import UUID

from aegisnet.domain.enums import ServiceTokenRole, UserRole


@unique
class Permission(StrEnum):
    meta_read = "meta.read"
    auth_self = "auth.self"
    assets_read = "assets.read"
    assets_write = "assets.write"
    assets_admin = "assets.admin"
    events_read = "events.read"
    events_payload = "events.payload"
    ingest_read = "ingest.read"
    ingest_write = "ingest.write"
    ingest_import = "ingest.import"
    audit_read = "audit.read"
    alerts_read = "alerts.read"
    detections_read = "detections.read"
    detections_run = "detections.run"
    incidents_read = "incidents.read"
    incidents_write = "incidents.write"
    briefs_read = "briefs.read"
    briefs_generate = "briefs.generate"


_VIEWER: Final = frozenset(
    {
        Permission.meta_read,
        Permission.auth_self,
        Permission.assets_read,
        Permission.events_read,
        Permission.alerts_read,
        Permission.incidents_read,
        Permission.briefs_read,
    }
)
_ANALYST: Final = _VIEWER | frozenset(
    {
        Permission.assets_write,
        Permission.events_payload,
        Permission.ingest_read,
        Permission.detections_read,
        Permission.incidents_write,
        Permission.briefs_generate,
    }
)
_ADMIN: Final = _ANALYST | frozenset(
    {
        Permission.assets_admin,
        Permission.ingest_write,
        Permission.ingest_import,
        Permission.audit_read,
        Permission.detections_run,
    }
)
_INGEST_SERVICE: Final = frozenset({Permission.ingest_write, Permission.meta_read})

ROLE_PERMISSIONS: Final[dict[str, frozenset[Permission]]] = {
    UserRole.viewer.value: _VIEWER,
    UserRole.analyst.value: _ANALYST,
    UserRole.admin.value: _ADMIN,
    ServiceTokenRole.ingest_service.value: _INGEST_SERVICE,
}
"""The RBAC matrix (SECURITY.md). Keyed by role label so users and service tokens share it."""


@unique
class PrincipalKind(StrEnum):
    user = "user"
    service_token = "service_token"  # noqa: S105 - a kind label, not a credential


@dataclass(frozen=True, slots=True)
class Principal:
    """Who is calling. ``permissions`` is derived from ``role`` and never widened."""

    kind: PrincipalKind
    id: UUID
    role: str
    permissions: frozenset[Permission]
    email: str | None = None
    token_id: str | None = None
    """The access token's ``jti`` for users; lets logout deny it for its remaining life."""

    @property
    def subject(self) -> str:
        return f"{self.kind.value}:{self.id}"

    def can(self, permission: Permission) -> bool:
        return permission in self.permissions


def principal_for_user(
    user_id: UUID, role: UserRole, email: str, token_id: str | None = None
) -> Principal:
    return Principal(
        kind=PrincipalKind.user,
        id=user_id,
        role=role.value,
        permissions=ROLE_PERMISSIONS[role.value],
        email=email,
        token_id=token_id,
    )


def principal_for_service_token(token_id: UUID, role: ServiceTokenRole) -> Principal:
    return Principal(
        kind=PrincipalKind.service_token,
        id=token_id,
        role=role.value,
        permissions=ROLE_PERMISSIONS[role.value],
    )


# ---------------------------------------------------------------- passwords and tokens

PASSWORD_MIN_LENGTH: Final = 12
PASSWORD_MAX_LENGTH: Final = 128
TOKEN_BYTES: Final = 32


class PasswordPolicyError(ValueError):
    pass


def check_password_policy(password: str) -> None:
    """Length only, deliberately: composition rules push people to predictable patterns."""
    if len(password) < PASSWORD_MIN_LENGTH:
        raise PasswordPolicyError(f"password must be at least {PASSWORD_MIN_LENGTH} characters")
    if len(password) > PASSWORD_MAX_LENGTH:
        raise PasswordPolicyError(f"password must be at most {PASSWORD_MAX_LENGTH} characters")
    if password.strip() != password:
        raise PasswordPolicyError("password must not start or end with whitespace")


def generate_token() -> tuple[str, bytes]:
    """A high-entropy opaque token and the sha256 digest that is all we ever store."""
    plaintext = secrets.token_urlsafe(TOKEN_BYTES)
    return plaintext, hash_token(plaintext)


def hash_token(plaintext: str) -> bytes:
    return hashlib.sha256(plaintext.encode("utf-8")).digest()


def fingerprint(text: str | None) -> bytes | None:
    """sha256 of a user agent or address, so the value itself is never stored (T-2.4)."""
    if text is None or not text.strip():
        return None
    return hashlib.sha256(text.strip().encode("utf-8")).digest()


# ---------------------------------------------------------------- errors


class AuthError(Exception):
    """Base class. Messages are generic on purpose: they never say *why* (no enumeration)."""


class InvalidCredentialsError(AuthError):
    pass


class NotAuthenticatedError(AuthError):
    pass


class PermissionDeniedError(AuthError):
    def __init__(self, permission: Permission) -> None:
        self.permission = permission
        super().__init__("forbidden")


class RefreshReuseError(AuthError):
    """A rotated refresh token was presented again: the chain is revoked (T-2.4)."""
