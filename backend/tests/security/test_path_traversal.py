"""T-1.6: a dataset is reached only by registry id; the path is confined, symlink-free and
checksum-verified, and no error message reveals where anything lives."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from aegisnet.adapters.files.registry import (
    ChecksumMismatchError,
    DatasetNotFoundError,
    InvalidRegistryError,
    RegistryError,
    UnsafeDatasetPathError,
    load_registry,
    resolve_dataset,
)

pytestmark = pytest.mark.security

CONTENT = b'{"timestamp":"2026-09-01T10:00:00+0000","event_type":"flow"}\n'
SHA = hashlib.sha256(CONTENT).hexdigest()


def _registry_text(path: str, sha: str = SHA, dataset_id: str = "synthetic-ok") -> str:
    return (
        "version: 1\n"
        "datasets:\n"
        f"  - id: {dataset_id}\n"
        f"    path: {path}\n"
        f"    sha256: {sha}\n"
        "    format: suricata_eve_ndjson\n"
        "    licence: MIT\n"
        "    description: test corpus\n"
    )


@pytest.fixture
def samples(tmp_path: Path) -> Path:
    root = tmp_path / "samples"
    (root / "synthetic").mkdir(parents=True)
    (root / "synthetic" / "ok.ndjson").write_bytes(CONTENT)
    (root / "registry.yml").write_text(_registry_text("synthetic/ok.ndjson"))
    (tmp_path / "outside.ndjson").write_bytes(CONTENT)
    return root


def test_a_registered_dataset_resolves_to_its_real_file(samples: Path) -> None:
    registry = load_registry(samples)
    resolved = resolve_dataset(samples, registry, "synthetic-ok")
    assert resolved.path == (samples / "synthetic" / "ok.ndjson").resolve()
    assert resolved.entry.sha256 == SHA
    assert resolved.path.read_bytes() == CONTENT


@pytest.mark.parametrize(
    "dataset_id",
    ["missing", "../synthetic/ok", "synthetic/ok.ndjson", "SYNTHETIC-OK", "", "a" * 65, "x;rm"],
)
def test_unknown_or_malformed_ids_are_not_found_with_no_detail(
    samples: Path, dataset_id: str
) -> None:
    registry = load_registry(samples)
    with pytest.raises(DatasetNotFoundError) as excinfo:
        resolve_dataset(samples, registry, dataset_id)
    assert str(excinfo.value) == "unknown dataset"


@pytest.mark.parametrize(
    "path",
    [
        "../outside.ndjson",
        "synthetic/../../outside.ndjson",
        "/etc/passwd",
        "synthetic/./ok.ndjson",
        "synthetic\\ok.ndjson",
        "~/ok.ndjson",
        "",
    ],
)
def test_traversal_shaped_paths_are_rejected_when_the_registry_loads(
    samples: Path, path: str
) -> None:
    (samples / "registry.yml").write_text(_registry_text(path))
    with pytest.raises(InvalidRegistryError) as excinfo:
        load_registry(samples)
    assert "/" not in str(excinfo.value).replace("datasets.0.path", "")
    assert "outside" not in str(excinfo.value)


def test_a_symlinked_file_is_refused(samples: Path) -> None:
    link = samples / "synthetic" / "link.ndjson"
    link.symlink_to(samples.parent / "outside.ndjson")
    (samples / "registry.yml").write_text(_registry_text("synthetic/link.ndjson"))
    registry = load_registry(samples)
    with pytest.raises(UnsafeDatasetPathError, match="symbolic link"):
        resolve_dataset(samples, registry, "synthetic-ok")


def test_a_symlinked_directory_component_is_refused(samples: Path) -> None:
    elsewhere = samples.parent / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "ok.ndjson").write_bytes(CONTENT)
    (samples / "linked").symlink_to(elsewhere)
    (samples / "registry.yml").write_text(_registry_text("linked/ok.ndjson"))
    registry = load_registry(samples)
    with pytest.raises(UnsafeDatasetPathError, match="symbolic link"):
        resolve_dataset(samples, registry, "synthetic-ok")


def test_a_directory_or_a_missing_file_is_refused(samples: Path) -> None:
    (samples / "registry.yml").write_text(_registry_text("synthetic"))
    with pytest.raises(UnsafeDatasetPathError, match="not a regular file"):
        resolve_dataset(samples, load_registry(samples), "synthetic-ok")
    (samples / "registry.yml").write_text(_registry_text("synthetic/gone.ndjson"))
    with pytest.raises(UnsafeDatasetPathError, match="missing"):
        resolve_dataset(samples, load_registry(samples), "synthetic-ok")


def test_tampered_content_fails_the_checksum_before_it_is_read(samples: Path) -> None:
    (samples / "synthetic" / "ok.ndjson").write_bytes(CONTENT + b"extra\n")
    registry = load_registry(samples)
    with pytest.raises(ChecksumMismatchError):
        resolve_dataset(samples, registry, "synthetic-ok")


@pytest.mark.parametrize(
    "text",
    [
        "version: 2\ndatasets: []\n",
        "version: 1\n",
        "version: 1\ndatasets:\n  - id: a\n",
        "not: [valid",
        _registry_text("synthetic/ok.ndjson", sha="abc"),
        _registry_text("synthetic/ok.ndjson") + _registry_text("synthetic/ok.ndjson")[19:],
    ],
)
def test_malformed_registries_are_refused(samples: Path, text: str) -> None:
    (samples / "registry.yml").write_text(text)
    with pytest.raises(InvalidRegistryError):
        load_registry(samples)


def test_a_missing_registry_is_an_invalid_registry(tmp_path: Path) -> None:
    with pytest.raises(InvalidRegistryError, match="missing or unreadable"):
        load_registry(tmp_path)


def test_no_registry_error_message_contains_a_filesystem_path(samples: Path) -> None:
    cases = [
        lambda: resolve_dataset(samples, load_registry(samples), "nope"),
        lambda: load_registry(samples.parent / "absent"),
    ]
    (samples / "synthetic" / "ok.ndjson").write_bytes(b"changed")
    cases.append(lambda: resolve_dataset(samples, load_registry(samples), "synthetic-ok"))
    for case in cases:
        with pytest.raises(RegistryError) as excinfo:
            case()
        assert str(samples) not in str(excinfo.value)
        assert "tmp" not in str(excinfo.value)
