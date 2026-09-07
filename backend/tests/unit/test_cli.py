"""The operator CLI: argument handling and the database-free commands."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegisnet.cli import EXIT_FAILED, EXIT_USAGE, build_parser, main
from tests.conftest import REPO_ROOT, make_settings

pytestmark = pytest.mark.unit

SAMPLES = REPO_ROOT / "samples"


def test_datasets_lists_the_committed_registry(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--samples-dir", str(SAMPLES), "datasets"]) == 0
    payload = json.loads(capsys.readouterr().out.strip())
    ids = [entry["id"] for entry in payload["datasets"]]
    # The generated corpus, the one sanitised capture the isolated lab produced (ADR-021),
    # and the multi-stage correlation scenario (ADR-025).
    assert ids == [
        "synthetic-benign-baseline-01",
        "lab-capture-01",
        "demo-scenario-multi-stage-01",
    ]
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
    """Every one, taken from the parser rather than from a list somebody keeps up to date.

    It used to name five of the thirty, so a subcommand could ship undocumented — and seven had:
    `correlate`, `incidents`, `incident`, `brief`, `export`, `retention` and `eval-correlation`
    were absent from `backend/README.md`'s enumeration while this test stayed green.
    """
    parser = build_parser()
    text = parser.format_help()
    commands = sorted(
        name
        # argparse exposes no public API for enumerating subcommands.
        for action in parser._subparsers._group_actions
        for name in action.choices
    )
    assert len(commands) == 30, f"the parser declares {len(commands)} subcommands"
    missing = [command for command in commands if command not in text]
    assert not missing, f"undocumented in --help: {missing}"


# ---------------------------------------------------------------- the report export


def test_export_writes_the_document_and_not_json(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Every other command prints sorted JSON through `_emit`. This one must not: the point of
    an export is its bytes, and a JSON wrapper would put an escaping layer between the operator
    and the thing `make export > case.md` is supposed to produce (ADR-032)."""
    from io import StringIO

    from aegisnet import cli

    document = "# AEG\\-2026\\-0001 — a case\n\n> not redacted\n"
    monkeypatch.setattr(cli, "_run", lambda _settings, _action: ("AEG-2026-0001", document))

    out = StringIO()
    assert cli.cmd_export(object(), "AEG-2026-0001", out) == 0  # type: ignore[arg-type]
    assert out.getvalue() == document, "byte for byte, with nothing added"
    assert capsys.readouterr().out == "", "and nothing on stdout beside it"


def test_export_of_an_unknown_case_fails_the_way_every_other_command_does(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from io import StringIO

    from aegisnet import cli

    monkeypatch.setattr(cli, "_run", lambda _settings, _action: None)
    out = StringIO()
    assert cli.cmd_export(object(), "AEG-2026-9999", out) == EXIT_FAILED  # type: ignore[arg-type]
    assert out.getvalue() == "", "no half a document"
    assert json.loads(capsys.readouterr().out) == {"error": "no incident AEG-2026-9999"}


def test_export_of_a_uuid_that_is_not_a_case_prints_an_envelope_not_a_traceback(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A case *number* that does not exist comes back as `None` and is handled in the command.
    A well-formed uuid that does not exist takes the other branch, reaches the store, and comes
    back as an exception — which `main` has to know about, or the operator gets a stack trace
    where every other command prints `{"error": ...}`. `brief` had the same hole."""
    from aegisnet import cli
    from aegisnet.services.brief_service import BriefIncidentNotFoundError
    from aegisnet.services.report_service import ReportIncidentNotFoundError

    missing = "00000000-0000-0000-0000-000000000000"
    for command, error in (
        ("export", ReportIncidentNotFoundError(missing)),
        ("brief", BriefIncidentNotFoundError(missing)),
    ):

        def raise_it(_settings: object, _action: object, err: Exception = error) -> None:
            raise err

        monkeypatch.setattr(cli, "_run", raise_it)
        monkeypatch.setattr(cli, "get_settings", make_settings)
        monkeypatch.setattr(cli, "configure_logging", lambda **_kwargs: None)
        assert cli.main([command, missing]) == EXIT_FAILED, command
        assert json.loads(capsys.readouterr().out) == {"error": missing}, command
