"""The Chunk 5 CLI commands: argument handling and the seed-file loader (no database)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from ipaddress import ip_address, ip_network
from pathlib import Path

import pytest

from aegisnet.adapters.files.registry import UnsafeDatasetPathError
from aegisnet.cli import EXIT_USAGE, build_parser, load_seed_file, main
from aegisnet.domain.enums import AssetEnvironment
from tests.conftest import REPO_ROOT

pytestmark = pytest.mark.unit

SAMPLES = REPO_ROOT / "samples"


def test_the_committed_seed_file_loads_and_is_overlap_free() -> None:
    specs = load_seed_file(SAMPLES, "lab-assets")
    assert len(specs) == 14
    assert all(spec.hostname and spec.hostname.endswith(".lab.example.test") for spec in specs)
    assert all(spec.environment is AssetEnvironment.lab for spec in specs)
    cidrs = [network.cidr for spec in specs for network in spec.networks]
    assert len(set(cidrs)) == len(cidrs)
    for index, cidr in enumerate(cidrs):
        assert not any(cidr.overlaps(other) for other in cidrs[index + 1 :]), cidr
    assert all(cidr.subnet_of(ip_network("10.10.0.0/24")) for cidr in cidrs)  # type: ignore[arg-type]


@pytest.mark.parametrize("name", ["", "../registry", "sub/dir", "with space", "a.b"])
def test_seed_names_are_plain_file_names(name: str) -> None:
    with pytest.raises(ValueError, match="seed name"):
        load_seed_file(SAMPLES, name)


def test_seed_files_are_confined_to_the_samples_directory(tmp_path: Path) -> None:
    samples = tmp_path / "samples"
    (samples / "assets").mkdir(parents=True)
    with pytest.raises(UnsafeDatasetPathError):
        load_seed_file(samples, "missing")
    (samples / "assets" / "bad.yml").write_text("assets: notalist\n")
    with pytest.raises(ValueError, match="'assets' list"):
        load_seed_file(samples, "bad")
    (samples / "assets" / "invalid.yml").write_text(
        "assets:\n  - hostname: bad host\n    environment: lab\n"
    )
    with pytest.raises(Exception, match="hostname"):
        load_seed_file(samples, "invalid")


def test_event_query_arguments_parse_into_typed_values() -> None:
    args = build_parser().parse_args(
        [
            "events",
            "--from",
            "2026-09-01T00:00:00Z",
            "--to",
            "2026-09-02T00:00:00+00:00",
            "--type",
            "dns",
            "--type",
            "http",
            "--src-ip",
            "10.10.0.0/24",
            "--dest-ip",
            "203.0.113.10",
            "--dest-port",
            "53",
            "--limit",
            "5",
            "--payload",
        ]
    )
    assert args.time_from == datetime(2026, 9, 1, tzinfo=UTC)
    assert args.types == ["dns", "http"]
    assert args.src_ip == ip_network("10.10.0.0/24")
    assert args.dest_ip == ip_address("203.0.113.10")
    assert args.dest_ports == [53] and args.limit == 5 and args.payload is True


@pytest.mark.parametrize(
    "argv",
    [
        ["events", "--from", "2026-09-01T00:00:00", "--to", "2026-09-02T00:00:00Z"],
        ["events", "--from", "2026-09-01T00:00:00Z"],
        ["events", "--from", "2026-09-01T00:00:00Z", "--to", "x", "--type", "bogus"],
        [
            "events",
            "--from",
            "2026-09-01T00:00:00Z",
            "--to",
            "2026-09-02T00:00:00Z",
            "--src-ip",
            "10.0.0.1/24",
        ],
        ["resolve", "not-an-ip"],
        ["assets", "--environment", "moon"],
        ["batches", "--status", "sideways"],
        ["asset", "nope"],
        ["seed-assets"],
    ],
)
def test_usage_errors_for_the_inventory_commands(argv: list[str]) -> None:
    with pytest.raises(SystemExit) as excinfo:
        build_parser().parse_args(argv)
    assert excinfo.value.code == 2


def test_seed_command_reports_a_bad_name_without_touching_the_database(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["--samples-dir", str(SAMPLES), "seed-assets", "../x"]) == EXIT_USAGE
    assert "seed name" in json.loads(capsys.readouterr().out)["error"]


def test_help_lists_every_command() -> None:
    text = build_parser().format_help()
    for command in (
        "datasets",
        "import-dataset",
        "batch",
        "batches",
        "rejects",
        "seed-assets",
        "assets",
        "asset",
        "resolve",
        "events",
        "event-stats",
    ):
        assert command in text
