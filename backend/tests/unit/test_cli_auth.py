"""The auth CLI commands: argument handling, the stdin password path, the public views."""

from __future__ import annotations

import io
import json
from datetime import UTC, datetime
from uuid import uuid4

import pytest

from aegisnet.cli import (
    EXIT_USAGE,
    build_parser,
    main,
    public_service_token,
    public_user,
    read_password,
)
from aegisnet.domain.auth import PasswordPolicyError
from aegisnet.domain.enums import ServiceTokenRole, UserRole
from aegisnet.domain.ports import ServiceTokenRecord, UserRecord

pytestmark = pytest.mark.unit

NOW = datetime(2026, 9, 5, tzinfo=UTC)


@pytest.mark.parametrize(
    "argv",
    [
        ["create-user", "a@example.test", "--role", "admin"],
        ["create-user", "a@example.test", "--password-stdin"],
        ["create-user", "a@example.test", "--role", "root", "--password-stdin"],
        ["create-user", "a@example.test", "--role", "admin", "--password", "x", "--password-stdin"],
        ["create-service-token", "x", "--ttl-days", "0"],
        ["create-service-token", "x", "--ttl-days", "366"],
        ["create-service-token", "x", "--ttl-days", "soon"],
        ["revoke-service-token", "not-a-uuid"],
    ],
)
def test_usage_errors_exit_with_status_two(argv: list[str]) -> None:
    with pytest.raises(SystemExit) as excinfo:
        build_parser().parse_args(argv)
    assert excinfo.value.code == 2


def test_the_password_comes_from_stdin_and_is_checked_before_any_connection(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO("short\n"))
    code = main(["create-user", "a@example.test", "--role", "viewer", "--password-stdin"])
    assert code == EXIT_USAGE
    assert "at least 12" in json.loads(capsys.readouterr().out)["error"]


def test_read_password_takes_one_line_and_applies_the_policy() -> None:
    stream = io.StringIO("correct horse battery\r\nsecond line\n")
    assert read_password(stream) == "correct horse battery"
    with pytest.raises(PasswordPolicyError):
        read_password(io.StringIO(" padded password 1\n"))
    with pytest.raises(PasswordPolicyError):
        read_password(io.StringIO(""))


def test_a_service_token_name_is_bounded_before_any_connection(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["create-service-token", "x" * 65]) == EXIT_USAGE
    assert "1 to 64" in json.loads(capsys.readouterr().out)["error"]


def test_public_views_never_carry_hashes() -> None:
    user = UserRecord(
        uuid4(), "a@example.test", "A", "$argon2id$hash", UserRole.admin, True, 0, None, None, NOW
    )
    token = ServiceTokenRecord(
        uuid4(), "sensor", b"\x00" * 32, ServiceTokenRole.ingest_service, None, NOW, None, None, NOW
    )
    view = public_user(user)
    assert "password_hash" not in view and "$argon2id$hash" not in json.dumps(view, default=str)
    assert view["role"] is UserRole.admin
    assert "token_hash" not in public_service_token(token)


def test_help_documents_the_auth_commands() -> None:
    text = build_parser().format_help()
    for command in (
        "create-user",
        "users",
        "create-service-token",
        "revoke-service-token",
        "service-tokens",
    ):
        assert command in text
