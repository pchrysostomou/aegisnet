"""`make bootstrap` guarantees from ADR-011, exercised against a temporary checkout.

The script takes no path — both files are resolved from the checkout it lives in, because a
path from `argv` reaching file I/O is the taint finding this project has removed four times.
So the tests build a fake checkout in `tmp_path` and point `_repo_root` at it, which also means
they can never touch the real `.env`.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

from tests.conftest import REPO_ROOT

pytestmark = pytest.mark.unit

SCRIPT = REPO_ROOT / "infra" / "scripts" / "bootstrap_env.py"
EXAMPLE = REPO_ROOT / ".env.example"
GENERATED_KEYS = {
    "SECRET_KEY",
    "POSTGRES_SUPERUSER_PASSWORD",
    "POSTGRES_APP_PASSWORD",
    "POSTGRES_MIGRATOR_PASSWORD",
    "POSTGRES_RETENTION_PASSWORD",
    "REDIS_PASSWORD",
}


@pytest.fixture(scope="module")
def bootstrap() -> ModuleType:
    spec = importlib.util.spec_from_file_location("bootstrap_env", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def checkout(bootstrap: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A directory that looks like a checkout: the real template, no .env yet."""
    (tmp_path / ".env.example").write_text(EXAMPLE.read_text(encoding="utf-8"), encoding="utf-8")
    monkeypatch.setattr(bootstrap, "_repo_root", lambda: tmp_path)
    return tmp_path


def _run(bootstrap: ModuleType, *extra: str) -> int:
    return int(bootstrap.main([*extra]))


def _assignments(path: Path) -> dict[str, str]:
    pairs = (
        line.split("=", 1)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line and not line.lstrip().startswith("#") and "=" in line
    )
    return dict(pairs)


def test_every_placeholder_is_replaced_with_a_distinct_secret(
    bootstrap: ModuleType, checkout: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = checkout / ".env"
    assert _run(bootstrap) == 0
    values = _assignments(out)
    assert not any(bootstrap.PLACEHOLDER in value for value in values.values())
    generated = [values[key] for key in GENERATED_KEYS]
    assert len(set(generated)) == len(GENERATED_KEYS), "secrets must be independent"
    assert all(len(value) >= 32 for value in generated)
    captured = capsys.readouterr()
    for value in generated:
        assert value not in captured.out
        assert value not in captured.err


def test_comment_lines_keep_their_placeholder_text(bootstrap: ModuleType, checkout: Path) -> None:
    out = checkout / ".env"
    _run(bootstrap)
    comments = [
        line for line in out.read_text(encoding="utf-8").splitlines() if line.startswith("#")
    ]
    assert any(bootstrap.PLACEHOLDER in line for line in comments)


def test_existing_env_is_never_overwritten_without_force(
    bootstrap: ModuleType, checkout: Path
) -> None:
    out = checkout / ".env"
    out.write_text("KEEP=me\n", encoding="utf-8")
    assert _run(bootstrap) == 0
    assert out.read_text(encoding="utf-8") == "KEEP=me\n"
    assert _run(bootstrap, "--force") == 0
    assert "KEEP=me" not in out.read_text(encoding="utf-8")


def test_add_missing_appends_only_what_is_absent(bootstrap: ModuleType, checkout: Path) -> None:
    """The upgrade path: a release adds a variable, and an existing .env must gain it without
    a single existing line changing — losing a password here would cost a database."""
    out = checkout / ".env"
    out.write_text("POSTGRES_APP_PASSWORD=keep-this-one\nUNKNOWN=mine\n", encoding="utf-8")

    assert _run(bootstrap, "--add-missing") == 0
    values = _assignments(out)

    assert values["POSTGRES_APP_PASSWORD"] == "keep-this-one", "an existing value is never touched"
    assert values["UNKNOWN"] == "mine", "and neither is a key the template has never heard of"
    assert values["POSTGRES_RETENTION_USER"] == "aegisnet_retention"
    assert bootstrap.PLACEHOLDER not in values["POSTGRES_RETENTION_PASSWORD"]
    assert len(values["POSTGRES_RETENTION_PASSWORD"]) >= 32


def test_add_missing_on_a_complete_file_changes_nothing(
    bootstrap: ModuleType, checkout: Path
) -> None:
    out = checkout / ".env"
    _run(bootstrap)
    before = out.read_text(encoding="utf-8")
    assert _run(bootstrap, "--add-missing") == 0
    assert out.read_text(encoding="utf-8") == before


def test_missing_template_is_an_error(
    bootstrap: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(bootstrap, "_repo_root", lambda: tmp_path)  # no .env.example in it
    assert bootstrap.main([]) == 2


def test_generated_secrets_are_safe_for_the_postgres_init_script(
    bootstrap: ModuleType, checkout: Path
) -> None:
    """01_roles.sh interpolates secrets into SQL and allows only the URL-safe alphabet."""
    out = checkout / ".env"
    _run(bootstrap)
    allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-=+/.")
    values = _assignments(out)
    for key in (
        "POSTGRES_APP_PASSWORD",
        "POSTGRES_MIGRATOR_PASSWORD",
        "POSTGRES_RETENTION_PASSWORD",
    ):
        assert set(values[key]) <= allowed
        assert len(values[key]) >= 16
