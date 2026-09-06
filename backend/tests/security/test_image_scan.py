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

import re
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
    assert not missing_pulled, (
        f"these images are pulled by the stack and never scanned: {sorted(missing_pulled)}"
    )
    # One scan target per distinct build, named after the compose project's image naming.
    assert len(built) == 2, f"the stack builds {len(built)} distinct images; the job scans 2"
    assert {"aegisnet-api:latest", "aegisnet-web:latest"} <= scanned


BUILT_HERE = "aegisnet-"


def test_a_finding_in_an_image_this_project_builds_fails_the_job() -> None:
    """Where the gate belongs: on the images where a finding is actionable.

    For the api and the dashboard the job is the gate, and Chunk 30 proved the gate is worth
    having: it found npm's bundled `tar` and an openssl a release behind, and both were fixed
    rather than suppressed. A gate is stronger than a report, so these do not need one.
    """
    ours = [s for s in _scan_steps() if str(s["with"]["image-ref"]).startswith(BUILT_HERE)]
    assert ours, "nothing this project builds is scanned"
    for step in ours:
        assert str(step["with"].get("exit-code")) == "1", f"{step.get('name')} does not gate"
        assert step["with"].get("severity") == "HIGH,CRITICAL"


def _upload_steps() -> list[dict[str, Any]]:
    return [step for step in _job()["steps"] if "upload-sarif" in str(step.get("uses", ""))]


def test_the_report_only_scans_publish_where_a_finding_can_be_read() -> None:
    """The half of the decision that changed, and the reason it is a test rather than a comment.

    This assertion used to be its inverse — `"sarif" not in` the workflow at all — on the
    reasoning that code scanning was unavailable because the repository was private and a report
    nobody can open is not a control. **The repository was never private.** It has carried a
    `PublicEvent` at its `created_at` second since 2026-08-28; the belief came from an
    instruction that was recorded and never checked against the API, and it propagated into
    `THREAT_MODEL.md`, `ADR-037` and this file. The code-scanning API answers `no analysis
    found`, not `403`.

    So the premise is gone and the conclusion goes with it: the two scans that only *print* now
    publish, because a finding in the Security tab outlives a log line. The gate above is
    unchanged — this is the weaker half of the job getting somewhere durable to land, not the
    stronger half being relaxed into a report.
    """
    uploads = _upload_steps()
    assert uploads, "the report-only scans publish nowhere again"

    sarif_scans = [s for s in _scan_steps() if s["with"].get("format") == "sarif"]
    assert sarif_scans, "nothing is written in SARIF for those uploads to publish"

    # A gate is stronger than a report. If an image this project builds ever produced SARIF
    # instead of failing the job, that would be the gate quietly becoming a notification.
    for step in sarif_scans:
        assert not str(step["with"]["image-ref"]).startswith(BUILT_HERE), (
            f"{step.get('name')} reports on an image whose findings should fail the job"
        )

    # Distinct categories, or the second upload replaces the first and the Security tab shows
    # one datastore instead of two — a silent halving of the coverage this job claims.
    categories = [str(step["with"]["category"]) for step in uploads]
    assert len(categories) == len(set(categories)), f"uploads share a category: {categories}"

    written = {str(step["with"]["output"]) for step in sarif_scans}
    published = {str(step["with"]["sarif_file"]) for step in uploads}
    assert written == published, f"written {sorted(written)} but published {sorted(published)}"


def test_the_job_may_publish_and_the_lockfile_audits_may_not() -> None:
    """`security-events: write` is the one token in this workflow that can write anything.

    It belongs to the job that publishes and to no other. The workflow's default stays
    `contents: read`, so a compromised dependency in `pip-audit` cannot forge a code-scanning
    result that says the images are clean.
    """
    assert _workflow()["permissions"].get("security-events") is None, (
        "the whole workflow can publish; scope it to the job that needs to"
    )
    assert _job()["permissions"].get("security-events") == "write"


def test_an_image_this_project_only_pulls_is_reported_and_not_gated_on() -> None:
    """The decision this chunk changed its mind about, and why (R-10).

    The first version gated on every image. Then the scan ran: `postgres:16-alpine` carried
    twenty-seven HIGH findings in util-linux and the Go standard library on one architecture and
    a different set on another, none of them reachable from anything in this repository, and all
    of them fixable only by the image's publisher. The available responses were to wait or to
    stop using PostgreSQL. Gating on that would have made CI a coin flip on an upstream release
    schedule, which is how a gate becomes something people switch off — and enumerating CVE ids
    in an ignore file would have been the same thing, slower and harder to notice.

    So they are scanned, printed and re-scanned weekly, and they do not block a push. That is a
    weaker property than gating and it is written down rather than implied.
    """
    theirs = [s for s in _scan_steps() if not str(s["with"]["image-ref"]).startswith(BUILT_HERE)]
    assert theirs, "the images this project pulls are not scanned at all"
    for step in theirs:
        assert str(step["with"].get("exit-code")) == "0", (
            f"{step.get('name')} gates on an image nobody here can fix"
        )
        assert step["with"].get("severity") == "HIGH,CRITICAL", "it must still look"


def test_nothing_is_suppressed_by_an_ignore_file() -> None:
    """An ignore file was written for the datastore findings and then deleted, because listing
    CVE ids for an image somebody else builds is a treadmill that reads like diligence. Reporting
    without gating says the same thing honestly and does not rot."""
    assert not (REPO_ROOT / "infra" / "trivy").exists(), "the ignore file is back"
    for step in _scan_steps():
        assert not step["with"].get("trivyignores"), f"{step.get('name')} suppresses findings"


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


EXACT_RELEASE = re.compile(r"^v?\d+\.\d+\.\d+$")


def test_the_scanner_action_is_pinned_to_an_exact_release() -> None:
    """Every action in this repository is pinned; a scanner that could change under us is a
    scanner whose green means less than it looks.

    An exact `x.y.z`, with or without the `v` this publisher happens to use — not a moving major
    like `@v0` and not a branch. The first version of this test required a leading digit, which
    encoded a guess about the tag format rather than the property being asserted, and the guess
    was wrong: `aquasecurity/trivy-action` publishes `v0.36.0`, and the job failed on the runner
    with "unable to find version" before anything was scanned.
    """
    for step in _scan_steps():
        uses = str(step["uses"])
        assert "@" in uses, uses
        version = uses.split("@", 1)[1]
        assert EXACT_RELEASE.fullmatch(version), f"{uses} is not pinned to an exact release"


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
