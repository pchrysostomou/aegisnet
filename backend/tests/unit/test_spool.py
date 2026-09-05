"""The upload spool: caller-minted names, capped async writes, confinement, line reads."""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from aegisnet.adapters.files.ndjson import read_lines
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


async def test_writes_stream_under_the_cap_into_a_minted_name(tmp_path: Path) -> None:
    spool = Spool(tmp_path / "spool")
    name = spool.new_name()
    assert SPOOL_NAME.match(name) and name != spool.new_name()
    size = await spool.write(name, _chunks(b'{"a":1}\n', b"\n", b'{"b":2}\n'), max_bytes=1024)
    assert size == 17
    assert spool.open(name).read_bytes() == b'{"a":1}\n\n{"b":2}\n'
    assert [line async for line in spool.lines(name)] == [b'{"a":1}\n', b"\n", b'{"b":2}\n']
    assert spool.count_lines(name) == 2
    assert spool.count_lines(name, stop_above=1) == 2
    spool.remove(name)
    spool.remove(name)  # idempotent
    with pytest.raises(UnknownSpoolError):
        spool.open(name)


async def test_a_body_past_the_cap_is_discarded_before_it_is_kept(tmp_path: Path) -> None:
    spool = Spool(tmp_path)
    with pytest.raises(SpoolTooLargeError):
        await spool.write(spool.new_name(), _chunks(b"x" * 600, b"y" * 600), max_bytes=1000)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    "name",
    ["../etc/passwd", "/etc/passwd", "abc.ndjson", "0" * 32, "0" * 32 + ".NDJSON", ""],
)
async def test_only_spool_names_resolve(tmp_path: Path, name: str) -> None:
    spool = Spool(tmp_path)
    with pytest.raises(UnknownSpoolError):
        spool.open(name)
    with pytest.raises(UnknownSpoolError):
        spool.remove(name)
    with pytest.raises(UnknownSpoolError):
        await spool.write(name, _chunks(b"x"), max_bytes=10)
    with pytest.raises(UnknownSpoolError):
        async for _ in spool.lines(name):
            pass
    assert list(tmp_path.iterdir()) == []


async def test_read_lines_keeps_newlines_and_handles_a_missing_final_one(tmp_path: Path) -> None:
    path = tmp_path / "f.ndjson"
    path.write_bytes(b"one\ntwo\r\nthree")
    assert [line async for line in read_lines(path)] == [b"one\n", b"two\r\n", b"three"]


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
