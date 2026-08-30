"""T-5.4: the environment template carries no real value, and the ignore rules hold."""

from __future__ import annotations

import re

import pytest

from tests.conftest import REPO_ROOT

pytestmark = pytest.mark.security

ENV_EXAMPLE = REPO_ROOT / ".env.example"
GITIGNORE = REPO_ROOT / ".gitignore"
PRE_COMMIT = REPO_ROOT / ".pre-commit-config.yaml"
PLACEHOLDER = "__REPLACE_ME__"
SECRET_KEY_NAME = re.compile(r"(PASSWORD|SECRET|TOKEN|API[_-]?KEY)", re.IGNORECASE)


def _assignments() -> dict[str, str]:
    result: dict[str, str] = {}
    for line in ENV_EXAMPLE.read_text(encoding="utf-8").splitlines():
        if line and not line.startswith("#"):
            key, _, value = line.partition("=")
            result[key] = value
    return result


def test_every_secret_variable_is_a_placeholder() -> None:
    values = _assignments()
    secrets = {k: v for k, v in values.items() if SECRET_KEY_NAME.search(k)}
    assert secrets, "expected at least one secret variable in the template"
    for key, value in secrets.items():
        assert value == PLACEHOLDER, f"{key} carries a literal value"


def test_no_assignment_has_a_trailing_comment() -> None:
    """Compose env_file keeps a trailing `# comment` as part of the value."""
    for line in ENV_EXAMPLE.read_text(encoding="utf-8").splitlines():
        if line and not line.startswith("#"):
            assert "#" not in line, line


def test_template_defaults_to_development_with_debug_off() -> None:
    values = _assignments()
    assert values["ENV"] == "development"
    assert values["DEBUG"] == "false"


@pytest.mark.parametrize(
    "pattern",
    [
        ".env",
        "!.env.example",
        "*.pcap",
        "*.pcapng",
        "eve*.json",
        "docker-compose.override.yml",
        "samples/external/",
        "*.pem",
        "*.key",
    ],
)
def test_gitignore_blocks_secrets_and_captures(pattern: str) -> None:
    lines = {line.strip() for line in GITIGNORE.read_text(encoding="utf-8").splitlines()}
    assert pattern in lines


def test_pre_commit_refuses_dotenv_and_captures() -> None:
    text = PRE_COMMIT.read_text(encoding="utf-8")
    assert "id: forbid-dotenv" in text
    assert "id: forbid-captures" in text
    assert "id: gitleaks" in text
    assert "id: detect-private-key" in text
