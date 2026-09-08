"""T-5.1: both images end on a non-root user and never regain root."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from tests.conftest import REPO_ROOT

pytestmark = pytest.mark.security

BACKEND_DOCKERFILE = REPO_ROOT / "backend" / "Dockerfile"
FRONTEND_DOCKERFILE = REPO_ROOT / "frontend" / "Dockerfile"
DOCKERFILES = [BACKEND_DOCKERFILE, FRONTEND_DOCKERFILE]
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


def test_the_dashboard_runtime_ships_no_package_manager() -> None:
    """T-5.6, and the first thing the image scan found.

    `node:22-alpine` ships npm and corepack, and npm carries its own bundled dependency tree —
    tar, sigstore, pacote, `@npmcli`. `pnpm audit --prod` reads this app's lockfile and those
    packages are not in it, so both lockfile audits are structurally blind to them: the scan
    reported a CRITICAL in `tar` inside an image whose own dependencies were clean (E-91).

    A Next standalone server runs `node server.js` and uses neither tool, so they are deleted
    rather than upgraded — which removes the whole class instead of this month's instance, and
    takes away the most convenient way to install something into a container somebody has just
    got code execution in.
    """
    runtime = _stages(FRONTEND_DOCKERFILE)["runtime"]
    removed = " ".join(runtime)
    for tool in ("/usr/local/lib/node_modules/npm", "/usr/local/bin/npx", "corepack"):
        assert tool in removed, f"the runtime stage no longer removes {tool}"
    assert "rm -rf" in removed


def test_the_api_runtime_ships_no_package_manager() -> None:
    """The same argument as the dashboard, which nobody made for this image for three chunks.

    `python:3.12-slim-bookworm` ships pip. The application runs from `/opt/venv`, which the
    `deps` stage builds with uv and copies in whole, so nothing in this container installs
    anything at run time: pip is entirely attack surface and, on the day this was written, six
    advisories' worth of it — CVE-2025-8869, CVE-2026-1703, CVE-2026-3219, CVE-2026-6357,
    CVE-2026-8643 and CVE-2026-13346, every one with a fixed version available.

    **The gate never fired on any of them**, because they are MEDIUM and LOW and the gate is
    HIGH,CRITICAL. They were found by the SARIF report, which the trivy action writes at every
    severity — and that is the argument for keeping the report wider than the gate rather than
    trimming it to match.

    `ensurepip` goes with it. Leaving it means `python -m ensurepip` restores in one command
    what this deleted, and the scanner reads its bundled wheel as an installed package anyway.
    Verified by running the image, not by reading this line: `import pip` and `import ensurepip`
    both raise ModuleNotFoundError, no `pip*` remains in `/usr/local/bin`, and uvicorn, alembic,
    pgrep and `python -m aegisnet.cli --help` all still work.
    """
    runtime = _stages(BACKEND_DOCKERFILE)["runtime"]
    removed = " ".join(line for line in runtime if line.upper().startswith("RUN "))
    for tool in ("site-packages/pip", "ensurepip", "/usr/local/bin/pip"):
        assert tool in removed, f"the runtime stage no longer removes {tool}"
    assert "rm -rf" in removed


def test_the_api_runtime_takes_the_distribution_security_patches() -> None:
    """A tag-pinned base ships what Debian had patched when the base was published, and nothing
    later, for as long as nobody rebuilds it upstream.

    That is not a hypothetical either: `libpcre2-8-0` sat at `10.42-1` in every `aegisnet-api`
    container with five advisories against it, all fixed in `10.42-1+deb12u1` — a package
    already in the suite this build reads from, one `apt-get upgrade` away. The scan is what
    said so, and it said so only once the report covered severities the gate does not.

    hadolint's DL3005 forbids this and is waived in `.hadolint.yaml` with the reason: the rule
    defends build reproducibility, which F-5 already traded away by pinning a tag rather than a
    digest. If digest pinning ever lands (#14) the waiver should be reconsidered in the same
    change.
    """
    runtime = " ".join(_stages(BACKEND_DOCKERFILE)["runtime"])
    assert "apt-get upgrade" in runtime, "the runtime image no longer takes Debian's patches"
    assert "rm -rf /var/lib/apt/lists/*" in runtime, "the package lists are left in the image"


# ---------------------------------------------------------------- build arguments


@pytest.mark.parametrize("path", DOCKERFILES, ids=lambda p: p.parent.name)
def test_no_build_argument_is_baked_into_the_image(path: Path) -> None:
    """A build argument must not be persisted into `ENV`, a `LABEL`, or anything else that
    survives into the image.

    This has cost two SonarCloud findings in the same file, and the first fix read the lesson too
    narrowly. Chunk 32 removed `LABEL org.opencontainers.image.revision="${GIT_SHA}"` from
    `backend/Dockerfile` after four bisection rounds (E-96) and treated it as being about the
    label. It was about the *pattern*: `ARG GIT_SHA` plus `ENV GIT_SHA=${GIT_SHA}` was left in
    place, does exactly the same thing, and cost ten more rounds to find (E-100).

    Why it is a vulnerability whatever the value happens to be: a build argument is how secrets
    are most often handed to a build, and `ENV`/`LABEL` write it into image metadata that
    `docker history` prints to anybody holding the image. An analyser cannot know that this
    particular one is a commit hash, and should not have to.

    `GIT_SHA` still reaches the running container — from Compose, as a runtime variable — so
    `/api/v1/meta/version` is unchanged. That is also the better arrangement: the image no longer
    claims to be one revision, so one build can serve any of them.
    """
    declared: set[str] = set()
    for line in _instructions(path):
        upper = line.upper()
        if upper.startswith("ARG "):
            declared.add(line.split(None, 1)[1].split("=", 1)[0].strip())
            continue
        if not (upper.startswith("ENV ") or upper.startswith("LABEL ")):
            continue
        baked = sorted(name for name in declared if f"${{{name}}}" in line or f"${name}" in line)
        assert not baked, (
            f"{path.parent.name}/Dockerfile bakes the build argument(s) {baked} into "
            f"{line.split(None, 1)[0]}: {line[:90]}"
        )


@pytest.mark.parametrize("path", DOCKERFILES, ids=lambda p: p.parent.name)
def test_every_build_argument_is_declared_before_it_is_used(path: Path) -> None:
    """The base-image arguments are the only ones either file should still need.

    Left as an assertion rather than a comment because the compose files pass build arguments by
    name: one passed to a stage that never declares it is silently ignored, which is how
    `GIT_SHA` kept being sent to three services after the Dockerfile stopped wanting it.
    """
    declared = {
        line.split(None, 1)[1].split("=", 1)[0].strip()
        for line in _instructions(path)
        if line.upper().startswith("ARG ")
    }
    assert declared <= {"UV_IMAGE", "PY_IMAGE", "NODE_IMAGE", "BASE_IMAGE"}, (
        f"{path.parent.name}/Dockerfile declares build arguments beyond the base images: "
        f"{sorted(declared)}"
    )


@pytest.mark.parametrize("path", DOCKERFILES, ids=lambda p: p.parent.name)
def test_no_dependency_is_installed_from_source(path: Path) -> None:
    """Installing a source distribution runs its build backend — arbitrary Python, at image-build
    time, with the network and the build context in reach. `--frozen` pins *what* is installed
    and does nothing about *what runs while installing it*; `--no-build` is the half that closes
    it, and `--ignore-scripts` is the same idea for npm lifecycle scripts.

    Asserted rather than commented because it is invisible when it is right and silent when it is
    wrong: a dependency that starts shipping sdist-only would quietly regain the ability to
    execute code here, and nothing else in the suite would notice.

    This is `docker:S8541` and `docker:S6505`, and they were the whole of the SonarCloud finding
    that ten rounds of bisection spent an afternoon locating — see E-100.
    """
    for line in _instructions(path):
        if "uv sync" in line or "uv pip install" in line:
            assert "--no-build" in line, f"{path.parent.name}/Dockerfile: {line[:80]}"
        if "pnpm install" in line or "npm install" in line or "npm ci" in line:
            assert "--ignore-scripts" in line, f"{path.parent.name}/Dockerfile: {line[:80]}"
