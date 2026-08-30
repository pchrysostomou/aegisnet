"""T-5.1: both images end on a non-root user and never regain root."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from tests.conftest import REPO_ROOT

pytestmark = pytest.mark.security

DOCKERFILES = [REPO_ROOT / "backend" / "Dockerfile", REPO_ROOT / "frontend" / "Dockerfile"]
FROM_LINE = re.compile(r"^FROM\s+(?P<image>\S+)(?:\s+AS\s+(?P<stage>\S+))?", re.IGNORECASE)


def _instructions(path: Path) -> list[str]:
    """Logical instructions with continuation lines joined and comments removed."""
    text = path.read_text(encoding="utf-8")
    joined = re.sub(r"\\\r?\n", " ", text)
    return [
        line.strip()
        for line in joined.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def _stages(path: Path) -> dict[str, list[str]]:
    stages: dict[str, list[str]] = {}
    current: list[str] | None = None
    for line in _instructions(path):
        match = FROM_LINE.match(line)
        if match:
            current = stages.setdefault(match.group("stage") or match.group("image"), [])
            continue
        if current is not None:
            current.append(line)
    return stages


def _last_user(lines: list[str]) -> str | None:
    users = [line.split(None, 1)[1] for line in lines if line.upper().startswith("USER ")]
    return users[-1] if users else None


@pytest.mark.parametrize("path", DOCKERFILES, ids=lambda p: p.parent.name)
def test_runtime_stage_ends_as_a_non_root_user(path: Path) -> None:
    stages = _stages(path)
    assert "runtime" in stages, "the Compose manifests target a stage named runtime"
    user = _last_user(stages["runtime"])
    assert user not in (None, "root", "0"), f"{path}: runtime stage runs as {user!r}"


def test_backend_dev_stage_used_by_the_test_runner_is_non_root() -> None:
    stages = _stages(DOCKERFILES[0])
    assert _last_user(stages["dev"]) == "aegisnet"


@pytest.mark.parametrize("path", DOCKERFILES, ids=lambda p: p.parent.name)
def test_no_stage_switches_back_to_root_after_dropping_it(path: Path) -> None:
    for name, lines in _stages(path).items():
        seen_non_root = False
        for line in lines:
            if line.upper().startswith("USER "):
                user = line.split(None, 1)[1]
                if user in ("root", "0"):
                    assert not seen_non_root, f"{path}:{name} regains root"
                else:
                    seen_non_root = True


@pytest.mark.parametrize("path", DOCKERFILES, ids=lambda p: p.parent.name)
def test_no_remote_add_or_piped_installers(path: Path) -> None:
    for line in _instructions(path):
        assert not re.match(r"^ADD\s+https?://", line, re.IGNORECASE), line
        assert not re.search(r"curl[^|]*\|\s*(ba)?sh", line), line
        assert not re.search(r"wget[^|]*\|\s*(ba)?sh", line), line


@pytest.mark.parametrize("path", DOCKERFILES, ids=lambda p: p.parent.name)
def test_base_images_are_pinned_by_tag(path: Path) -> None:
    for line in _instructions(path):
        if line.upper().startswith("ARG ") and "_IMAGE=" in line:
            image = line.split("=", 1)[1]
            assert ":" in image and not image.endswith(":latest"), line
