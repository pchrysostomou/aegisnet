"""`make bootstrap` guarantees from ADR-011, exercised against a temporary copy."""

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


def _run(bootstrap: ModuleType, out: Path, *extra: str) -> int:
    return int(bootstrap.main(["--example", str(EXAMPLE), "--out", str(out), *extra]))


def _assignments(path: Path) -> dict[str, str]:
    pairs = (
        line.split("=", 1)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line and not line.lstrip().startswith("#") and "=" in line
    )
    return dict(pairs)


def test_every_placeholder_is_replaced_with_a_distinct_secret(
    bootstrap: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / ".env"
    assert _run(bootstrap, out) == 0
    values = _assignments(out)
    assert not any(bootstrap.PLACEHOLDER in value for value in values.values())
    generated = [values[key] for key in GENERATED_KEYS]
    assert len(set(generated)) == len(GENERATED_KEYS), "secrets must be independent"
    assert all(len(value) >= 32 for value in generated)
    captured = capsys.readouterr()
    for value in generated:
        assert value not in captured.out
        assert value not in captured.err


def test_comment_lines_keep_their_placeholder_text(bootstrap: ModuleType, tmp_path: Path) -> None:
    out = tmp_path / ".env"
    _run(bootstrap, out)
    comments = [
        line for line in out.read_text(encoding="utf-8").splitlines() if line.startswith("#")
    ]
    assert any(bootstrap.PLACEHOLDER in line for line in comments)


def test_existing_env_is_never_overwritten_without_force(
    bootstrap: ModuleType, tmp_path: Path
) -> None:
    out = tmp_path / ".env"
    out.write_text("KEEP=me\n", encoding="utf-8")
    assert _run(bootstrap, out) == 0
    assert out.read_text(encoding="utf-8") == "KEEP=me\n"
    assert _run(bootstrap, out, "--force") == 0
    assert "KEEP=me" not in out.read_text(encoding="utf-8")


def test_missing_template_is_an_error(bootstrap: ModuleType, tmp_path: Path) -> None:
    code = bootstrap.main(["--example", str(tmp_path / "nope"), "--out", str(tmp_path / ".env")])
    assert code == 2


def test_generated_secrets_are_safe_for_the_postgres_init_script(
    bootstrap: ModuleType, tmp_path: Path
) -> None:
    """01_roles.sh interpolates secrets into SQL and allows only the URL-safe alphabet."""
    out = tmp_path / ".env"
    _run(bootstrap, out)
    allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-=+/.")
    values = _assignments(out)
    for key in ("POSTGRES_APP_PASSWORD", "POSTGRES_MIGRATOR_PASSWORD"):
        assert set(values[key]) <= allowed
        assert len(values[key]) >= 16
