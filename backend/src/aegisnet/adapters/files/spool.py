"""Upload spool: where an ingest body waits between the request and the worker (T-1.4).

Bytes are streamed to a file under ``SPOOL_DIR`` with a hard cap; a body that grows past
the cap is discarded before anything parses it. Names are random and the directory is the
only place a name is ever resolved, so a message carrying a spool name (TB-5: ids only)
cannot point anywhere else.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path
from typing import Final

SPOOL_NAME: Final = re.compile(r"^[0-9a-f]{32}\.ndjson$")


class SpoolError(Exception):
    pass


class SpoolTooLargeError(SpoolError):
    pass


class UnknownSpoolError(SpoolError):
    pass


@dataclass(frozen=True, slots=True)
class Spooled:
    name: str
    size: int


class Spool:
    def __init__(self, directory: Path) -> None:
        self._dir = directory

    def ensure_writable(self) -> Path:
        """Create the directory if needed and prove a file can be written there, so a
        wrong volume ownership fails at startup instead of on the first upload."""
        try:
            self._dir.mkdir(parents=True, exist_ok=True)
            probe = self._dir / f".probe-{uuid.uuid4().hex}"
            probe.write_bytes(b"")
            probe.unlink()
        except OSError as error:
            raise SpoolError(f"spool directory is not writable: {error.strerror}") from error
        return self._dir

    def _path(self, name: str) -> Path:
        if not SPOOL_NAME.match(name):
            raise UnknownSpoolError("unknown spool entry")
        return self._dir / name

    async def write(self, chunks: AsyncIterator[bytes], *, max_bytes: int) -> Spooled:
        self._dir.mkdir(parents=True, exist_ok=True)
        name = f"{uuid.uuid4().hex}.ndjson"
        path = self._dir / name
        size = 0
        try:
            with path.open("wb") as handle:
                async for chunk in chunks:
                    size += len(chunk)
                    if size > max_bytes:
                        raise SpoolTooLargeError(f"body exceeds {max_bytes} bytes")
                    handle.write(chunk)
        except BaseException:
            path.unlink(missing_ok=True)
            raise
        return Spooled(name=name, size=size)

    def open(self, name: str) -> Path:
        path = self._path(name)
        if not path.is_file():
            raise UnknownSpoolError("unknown spool entry")
        return path

    def remove(self, name: str) -> None:
        self._path(name).unlink(missing_ok=True)

    def count_lines(self, name: str, *, stop_above: int | None = None) -> int:
        """Non-blank lines, scanning without parsing; stops early once past ``stop_above``."""
        count = 0
        with self.open(name).open("rb") as handle:
            for line in handle:
                if line.strip():
                    count += 1
                    if stop_above is not None and count > stop_above:
                        return count
        return count
