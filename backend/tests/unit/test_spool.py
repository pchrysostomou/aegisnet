"""The upload spool: capped writes, random names, confinement, line counting."""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from aegisnet.adapters.files.spool import (
    SPOOL_NAME,
    Spool,
    SpoolError,
    SpoolTooLargeError,
    UnknownSpoolError,
)

pytestmark = pytest.mark.unit


async def _chunks(*parts: bytes) -> AsyncIterator[bytes]:
    for part in parts:
        yield part


async def test_writes_stream_under_the_cap_to_a_random_name(tmp_path: Path) -> None:
    spool = Spool(tmp_path / "spool")
    spooled = await spool.write(_chunks(b'{"a":1}\n', b"\n", b'{"b":2}\n'), max_bytes=1024)
    assert SPOOL_NAME.match(spooled.name) and spooled.size == 17
    assert spool.open(spooled.name).read_bytes() == b'{"a":1}\n\n{"b":2}\n'
    assert spool.count_lines(spooled.name) == 2
    assert spool.count_lines(spooled.name, stop_above=1) == 2
    spool.remove(spooled.name)
    spool.remove(spooled.name)  # idempotent
    with pytest.raises(UnknownSpoolError):
        spool.open(spooled.name)


async def test_a_body_past_the_cap_is_discarded_before_it_is_kept(tmp_path: Path) -> None:
    spool = Spool(tmp_path)
    with pytest.raises(SpoolTooLargeError):
        await spool.write(_chunks(b"x" * 600, b"y" * 600), max_bytes=1000)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    "name",
    ["../etc/passwd", "/etc/passwd", "abc.ndjson", "0" * 32, "0" * 32 + ".NDJSON", ""],
)
def test_only_spool_names_resolve(tmp_path: Path, name: str) -> None:
    with pytest.raises(UnknownSpoolError):
        Spool(tmp_path).open(name)
    with pytest.raises(UnknownSpoolError):
        Spool(tmp_path).remove(name)


def test_ensure_writable_creates_the_directory_and_refuses_one_it_cannot_write(
    tmp_path: Path,
) -> None:
    created = Spool(tmp_path / "nested" / "spool").ensure_writable()
    assert created.is_dir() and list(created.iterdir()) == []  # the probe file is gone
    blocked = tmp_path / "blocked"
    blocked.mkdir()
    blocked.chmod(0o500)
    try:
        with pytest.raises(SpoolError, match="not writable"):
            Spool(blocked).ensure_writable()
    finally:
        blocked.chmod(0o700)
