"""The detection CLI commands: argument handling and the interval check before any database."""

from __future__ import annotations

import json

import pytest

from aegisnet.cli import EXIT_USAGE, build_parser, main

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    "argv",
    [
        ["run-detectors"],
        ["run-detectors", "--from", "2026-09-01T00:00:00Z"],
        [
            "run-detectors",
            "--from",
            "2026-09-01T00:00:00Z",
            "--to",
            "2026-09-01T01:00:00Z",
            "--mode",
            "later",
        ],
        ["run-detectors", "--from", "2026-09-01T00:00:00", "--to", "2026-09-01T01:00:00Z"],
        ["alerts", "--severity-min", "9"],
        ["alerts", "--limit", "ten"],
        ["alert", "not-a-uuid"],
        ["detector-runs", "--limit", "x"],
        ["recompute-baselines", "--window-days", "0"],
        ["recompute-baselines", "--window-days", "91"],
        ["recompute-baselines", "--mode", "never"],
    ],
)
def test_usage_errors_exit_with_status_two(argv: list[str]) -> None:
    with pytest.raises(SystemExit) as excinfo:
        build_parser().parse_args(argv)
    assert excinfo.value.code == 2


def test_the_interval_is_checked_before_any_connection(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["run-detectors", "--from", "2026-09-01T02:00:00Z", "--to", "2026-09-01T01:00:00Z"])
    assert code == EXIT_USAGE
    assert "after its start" in json.loads(capsys.readouterr().out)["error"]
    code = main(["run-detectors", "--from", "2026-09-01T00:00:00Z", "--to", "2026-09-02T00:00:01Z"])
    assert code == EXIT_USAGE
    assert "at most" in json.loads(capsys.readouterr().out)["error"]


def test_help_documents_the_detection_commands() -> None:
    text = build_parser().format_help()
    for command in (
        "run-detectors",
        "alerts",
        "alert",
        "detector-runs",
        "recompute-baselines",
        "baselines",
    ):
        assert command in text
