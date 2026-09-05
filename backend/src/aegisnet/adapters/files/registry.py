"""Dataset registry: ``samples/registry.yml`` and the only way a file is ever imported.

THREAT_MODEL T-1.6: the import endpoint accepts a *dataset id*, never a path. The id is
matched against the registry, the registered relative path is resolved with ``realpath``
and must land inside ``samples/``, every path component is checked for symlinks, and the
file's sha256 must equal the recorded one before a byte of it is parsed. Anything else
raises, and the error types carry no path so a message cannot leak the layout.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Final, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

REGISTRY_FILE: Final = "registry.yml"
DATASET_ID: Final = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
SHA256_HEX: Final = re.compile(r"^[0-9a-f]{64}$")
_CHUNK: Final = 1024 * 1024


class RegistryError(Exception):
    """Base class; messages are safe to show to an operator, never contain a path."""


class DatasetNotFoundError(RegistryError):
    pass


class UnsafeDatasetPathError(RegistryError):
    pass


class ChecksumMismatchError(RegistryError):
    pass


class InvalidRegistryError(RegistryError):
    pass


class DatasetEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(pattern=DATASET_ID.pattern)
    path: str = Field(min_length=1, max_length=255)
    sha256: str = Field(pattern=SHA256_HEX.pattern)
    format: Literal["suricata_eve_ndjson"]
    licence: str = Field(min_length=1, max_length=200)
    citation: str | None = Field(default=None, max_length=1000)
    description: str = Field(min_length=1, max_length=1000)
    manifest: str | None = Field(default=None, max_length=255)

    @field_validator("path", "manifest")
    @classmethod
    def _relative_and_plain(cls, value: str | None) -> str | None:
        """Relative, forward-slash, no ``.``/``..`` components, no drive or root."""
        if value is None:
            return None
        # Split the raw text: PurePosixPath would silently collapse "." components.
        if value.startswith(("/", "~")) or "\\" in value:
            raise ValueError("path must be relative to samples/")
        if any(part in ("", ".", "..") for part in value.split("/")):
            raise ValueError("path must not contain empty, '.' or '..' components")
        return value


class Registry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal[1]
    datasets: list[DatasetEntry]

    @field_validator("datasets")
    @classmethod
    def _unique_ids(cls, value: list[DatasetEntry]) -> list[DatasetEntry]:
        ids = [entry.id for entry in value]
        if len(ids) != len(set(ids)):
            raise ValueError("dataset ids must be unique")
        return value

    def get(self, dataset_id: str) -> DatasetEntry:
        if not DATASET_ID.fullmatch(dataset_id):
            raise DatasetNotFoundError("unknown dataset")
        for entry in self.datasets:
            if entry.id == dataset_id:
                return entry
        raise DatasetNotFoundError("unknown dataset")


@dataclass(frozen=True, slots=True)
class ResolvedDataset:
    entry: DatasetEntry
    path: Path
    """Real, verified location of the file. Only :func:`resolve_dataset` produces one."""


def load_registry(samples_dir: Path) -> Registry:
    registry_path = samples_dir / REGISTRY_FILE
    try:
        raw = yaml.safe_load(registry_path.read_text(encoding="utf-8"))
    except OSError as error:
        raise InvalidRegistryError("registry file is missing or unreadable") from error
    except yaml.YAMLError as error:
        raise InvalidRegistryError("registry file is not valid YAML") from error
    try:
        return Registry.model_validate(raw)
    except ValidationError as error:
        problems = "; ".join(
            f"{'.'.join(str(part) for part in item['loc'])}: {item['type']}"
            for item in error.errors()[:5]
        )
        raise InvalidRegistryError(f"registry file is invalid: {problems}") from error


def _contained_real_path(samples_dir: Path, relative: str) -> Path:
    """Resolve ``relative`` under ``samples_dir`` refusing symlinks and escapes."""
    try:
        root = samples_dir.resolve(strict=True)
    except OSError as error:
        raise UnsafeDatasetPathError("samples directory is unavailable") from error
    candidate = root
    for part in PurePosixPath(relative).parts:
        candidate = candidate / part
        if candidate.is_symlink():
            raise UnsafeDatasetPathError("dataset path contains a symbolic link")
    try:
        real = candidate.resolve(strict=True)
    except OSError as error:
        raise UnsafeDatasetPathError("dataset file is missing") from error
    if real != candidate or not real.is_relative_to(root):
        raise UnsafeDatasetPathError("dataset path escapes the samples directory")
    if not real.is_file():
        raise UnsafeDatasetPathError("dataset path is not a regular file")
    return real


def sha256_of_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(_CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def resolve_dataset(samples_dir: Path, registry: Registry, dataset_id: str) -> ResolvedDataset:
    """Look the id up, confine the path, verify the checksum, and only then hand back a
    location. Raises a :class:`RegistryError` subclass otherwise."""
    entry = registry.get(dataset_id)
    real = _contained_real_path(samples_dir, entry.path)
    if sha256_of_file(real) != entry.sha256:
        raise ChecksumMismatchError("dataset content does not match the registered checksum")
    return ResolvedDataset(entry=entry, path=real)
