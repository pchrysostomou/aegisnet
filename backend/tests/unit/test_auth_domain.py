"""Auth value objects: the RBAC matrix, principals, the password policy, token helpers."""

from __future__ import annotations

import hashlib
from uuid import uuid4

import pytest

from aegisnet.domain.auth import (
    PASSWORD_MAX_LENGTH,
    PASSWORD_MIN_LENGTH,
    ROLE_PERMISSIONS,
    PasswordPolicyError,
    Permission,
    PermissionDeniedError,
    PrincipalKind,
    check_password_policy,
    fingerprint,
    generate_token,
    hash_token,
    principal_for_service_token,
    principal_for_user,
)
from aegisnet.domain.enums import ServiceTokenRole, UserRole

pytestmark = pytest.mark.unit


def test_user_roles_nest_and_admin_holds_every_permission() -> None:
    viewer = ROLE_PERMISSIONS[UserRole.viewer.value]
    analyst = ROLE_PERMISSIONS[UserRole.analyst.value]
    admin = ROLE_PERMISSIONS[UserRole.admin.value]
    assert viewer < analyst < admin
    assert admin == frozenset(Permission)


def test_the_viewer_reads_without_payloads_and_the_analyst_cannot_administer() -> None:
    viewer = ROLE_PERMISSIONS["viewer"]
    analyst = ROLE_PERMISSIONS["analyst"]
    assert viewer == {
        Permission.meta_read,
        Permission.auth_self,
        Permission.assets_read,
        Permission.events_read,
        Permission.alerts_read,
        # A case is the readable form of alerts a viewer may already read, so reading one
        # tells them nothing new; changing one is an analyst's job (ADR-024).
        Permission.incidents_read,
        # A brief is a narrative about those same alerts. *Asking* for one spends money and
        # sends a packet outside the deployment, which is an analyst's call (ADR-031).
        Permission.briefs_read,
    }
    assert {Permission.events_payload, Permission.assets_write, Permission.ingest_read} <= analyst
    assert Permission.incidents_write in analyst
    assert Permission.incidents_write not in viewer
    assert Permission.briefs_generate in analyst
    assert Permission.briefs_generate not in viewer
    admin_only = {
        Permission.assets_admin,
        Permission.ingest_write,
        Permission.ingest_import,
        Permission.audit_read,
        Permission.detections_run,
    }
    assert Permission.detections_read in analyst
    assert not analyst & admin_only


def test_the_ingest_service_role_can_only_ingest() -> None:
    assert ROLE_PERMISSIONS[ServiceTokenRole.ingest_service.value] == {
        Permission.ingest_write,
        Permission.meta_read,
    }


def test_principals_carry_their_role_permissions_and_a_stable_subject() -> None:
    user_id, token_id = uuid4(), uuid4()
    user = principal_for_user(user_id, UserRole.analyst, "a@example.test", token_id="jti-1")
    service = principal_for_service_token(token_id, ServiceTokenRole.ingest_service)
    assert user.kind is PrincipalKind.user and user.subject == f"user:{user_id}"
    assert user.can(Permission.events_payload) and not user.can(Permission.audit_read)
    assert user.token_id == "jti-1" and user.email == "a@example.test"
    assert service.subject == f"service_token:{token_id}"
    assert service.can(Permission.ingest_write) and not service.can(Permission.ingest_read)
    assert service.email is None and service.token_id is None


def test_principals_are_immutable() -> None:
    principal = principal_for_user(uuid4(), UserRole.viewer, "v@example.test")
    with pytest.raises(AttributeError):
        principal.permissions = frozenset(Permission)  # type: ignore[misc]


@pytest.mark.parametrize(
    ("password", "message"),
    [
        ("short", "at least 12"),
        ("x" * (PASSWORD_MAX_LENGTH + 1), "at most 128"),
        (" leading-space-pw", "whitespace"),
        ("trailing-space-pw ", "whitespace"),
    ],
)
def test_the_password_policy_rejects(password: str, message: str) -> None:
    with pytest.raises(PasswordPolicyError, match=message):
        check_password_policy(password)


def test_the_password_policy_is_length_only() -> None:
    check_password_policy("a" * PASSWORD_MIN_LENGTH)
    check_password_policy("correct horse battery staple")
    check_password_policy("x" * PASSWORD_MAX_LENGTH)


def test_tokens_are_random_url_safe_and_stored_only_as_sha256() -> None:
    first, first_hash = generate_token()
    second, _ = generate_token()
    assert first != second
    assert len(first) >= 40 and all(c.isalnum() or c in "-_" for c in first)
    assert first_hash == hashlib.sha256(first.encode()).digest() == hash_token(first)
    assert len(first_hash) == 32


def test_fingerprints_hide_the_value_and_ignore_blank_input() -> None:
    assert fingerprint(None) is None and fingerprint("   ") is None
    assert fingerprint(" Mozilla/5.0 ") == hashlib.sha256(b"Mozilla/5.0").digest()


def test_permission_denied_names_the_permission_and_nothing_else() -> None:
    error = PermissionDeniedError(Permission.audit_read)
    assert error.permission is Permission.audit_read
    assert str(error) == "forbidden"
