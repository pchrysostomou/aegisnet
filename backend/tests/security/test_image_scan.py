"""Nothing the stack runs goes unscanned (Milestone 6, Chunk 30; T-5.6).

`pip-audit` and `pnpm audit` read lockfiles, and a lockfile cannot see a base image. A CVE in
the distribution's openssl ships inside every container this project builds and appears in
neither audit. `THREAT_MODEL.md` has named an image scan since the planning phase and there was
none — the coverage matrix is what said so.

The workflow is the control; this file is what stops it drifting away from the stack it is meant
to cover. A seventh service, or a service that starts building from a different context, has to
be scanned or fail here.
"""

from __future__ import annotations

from typing import Any

import pytest
import yaml

from tests.conftest import REPO_ROOT

pytestmark = pytest.mark.security

SECURITY_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "security.yml"
COMPOSE = REPO_ROOT / "docker-compose.yml"
SCAN_JOB = "images"


def _workflow() -> dict[str, Any]:
    loaded = yaml.safe_load(SECURITY_WORKFLOW.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


def _job() -> dict[str, Any]:
    jobs = _workflow()["jobs"]
    assert SCAN_JOB in jobs, f"the security workflow no longer defines a {SCAN_JOB!r} job"
    job: dict[str, Any] = jobs[SCAN_JOB]
    return job


def _scan_steps() -> list[dict[str, Any]]:
    return [step for step in _job()["steps"] if "trivy-action" in str(step.get("uses", ""))]


def _services() -> dict[str, Any]:
    loaded = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    services: dict[str, Any] = loaded["services"]
    return services


def test_the_image_scan_covers_every_image_the_stack_runs() -> None:
    """The property worth having: a service added to the stack cannot go unscanned quietly.

    Services that build from the same context and target are the same image content under
    different names — api, worker and scheduler are one build — so the set compared here is
    *distinct images*, not service names.
    """
    scanned = {str(step["with"]["image-ref"]) for step in _scan_steps()}

    pulled = {str(service["image"]) for service in _services().values() if service.get("image")}
    built = {
        (str(service["build"]["context"]), str(service["build"].get("target")))
        for service in _services().values()
        if service.get("build")
    }

    missing_pulled = pulled - scanned
    assert (
        not missing_pulled
    ), f"these images are pulled by the stack and never scanned: {sorted(missing_pulled)}"
    # One scan target per distinct build, named after the compose project's image naming.
    assert len(built) == 2, f"the stack builds {len(built)} distinct images; the job scans 2"
    assert {"aegisnet-api:latest", "aegisnet-web:latest"} <= scanned


def test_the_scan_fails_the_job_rather_than_filing_a_report_nobody_reads() -> None:
    """Code scanning is not enabled on this repository — the API answers `403` — so a SARIF
    upload would go nowhere and the finding would be lost. The job has to be the gate."""
    for step in _scan_steps():
        options = step["with"]
        assert str(options.get("exit-code")) == "1", f"{step.get('name')} does not fail the job"
        assert options.get("severity") == "HIGH,CRITICAL"
    assert "sarif" not in SECURITY_WORKFLOW.read_text(encoding="utf-8").lower()


def test_unfixed_findings_do_not_turn_every_push_red() -> None:
    """A gate nobody can pass is a gate people learn to switch off.

    A base image carrying a CVE with no upstream fix would otherwise fail every push until
    somebody invented a fix that does not exist. Unfixed findings are still printed; they just
    do not block. That is a deliberate weakening and it is written down here so that changing
    it is a decision rather than an edit.
    """
    for step in _scan_steps():
        assert step["with"].get("ignore-unfixed") is True, step.get("name")


def test_the_scan_runs_on_every_push_and_again_on_a_schedule() -> None:
    """The weekly run matters more here than for the lockfile audits: the base images follow a
    moving tag (F-5, R-10), so what ships can change without a commit."""
    triggers = _workflow()[True] if True in _workflow() else _workflow()["on"]
    assert "push" in triggers and "schedule" in triggers


def test_the_scanner_action_is_pinned_to_an_exact_release() -> None:
    """Every action in this repository is pinned; a scanner that could change under us is a
    scanner whose green means less than it looks."""
    for step in _scan_steps():
        uses = str(step["uses"])
        assert "@" in uses, uses
        version = uses.split("@", 1)[1]
        assert version[0].isdigit(), f"{uses} is not pinned to an exact release"


def test_the_job_builds_what_it_scans_rather_than_scanning_a_stale_tag() -> None:
    """Scanning `aegisnet-api:latest` without building it would scan whatever the runner
    happened to have, which on a fresh runner is nothing at all."""
    commands = " ".join(str(step.get("run", "")) for step in _job()["steps"])
    assert "docker compose build api web" in commands
    for pulled in ("postgres:16-alpine", "redis:7-alpine"):
        assert f"docker pull {pulled}" in commands
    assert "bootstrap_env.py" in commands, "compose needs the variables even to build"


def test_the_lockfile_audits_are_still_there_because_the_scan_does_not_replace_them() -> None:
    """Trivy reads what is installed in the image; `pip-audit --strict` reads the resolved
    lockfile, including packages a build stage discards. They overlap and neither contains the
    other, so removing one because the other exists would be a loss."""
    jobs = _workflow()["jobs"]
    assert {"secrets", "python-deps", "node-deps", SCAN_JOB} <= set(jobs)
