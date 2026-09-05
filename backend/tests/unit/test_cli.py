"""The operator CLI: argument handling and the database-free commands."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegisnet.cli import EXIT_FAILED, EXIT_USAGE, build_parser, main
from tests.conftest import REPO_ROOT

pytestmark = pytest.mark.unit

SAMPLES = REPO_ROOT / "samples"


def test_datasets_lists_the_committed_registry(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--samples-dir", str(SAMPLES), "datasets"]) == 0
    payload = json.loads(capsys.readouterr().out.strip())
    ids = [entry["id"] for entry in payload["datasets"]]
    # The generated corpus, and the one sanitised capture the isolated lab produced (ADR-021).
    assert ids == ["synthetic-benign-baseline-01", "lab-capture-01"]
    assert payload["datasets"][0]["licence"].startswith("MIT")


def test_datasets_with_a_missing_registry_fails_without_a_path(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["--samples-dir", str(tmp_path), "datasets"]) == EXIT_FAILED
    out = capsys.readouterr().out
    assert json.loads(out) == {"error": "registry file is missing or unreadable"}
    assert str(tmp_path) not in out


def test_import_rejects_an_overlong_label_before_touching_anything(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code = main(["--samples-dir", str(SAMPLES), "import-dataset", "x", "--source-label", "l" * 65])
    assert code == EXIT_USAGE
    assert "1 to 64" in json.loads(capsys.readouterr().out)["error"]


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["import-dataset"],
        ["import-dataset", "x"],
        ["import-dataset", "x", "--source-label", "y", "--mode", "later"],
        ["batch", "not-a-uuid"],
        ["unknown"],
    ],
)
def test_usage_errors_exit_with_status_two(argv: list[str]) -> None:
    with pytest.raises(SystemExit) as excinfo:
        build_parser().parse_args(argv)
    assert excinfo.value.code == 2


def test_help_documents_every_command() -> None:
    text = build_parser().format_help()
    for command in ("datasets", "import-dataset", "batch"):
        assert command in text
