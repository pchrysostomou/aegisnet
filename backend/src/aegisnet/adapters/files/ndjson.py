"""Line-oriented reading of NDJSON files without blocking the event loop.

Both the dataset importer and the upload spool hand their bytes to
``IngestService.ingest`` one line at a time. Doing that through ``anyio`` keeps disk I/O
off the loop thread that also serves HTTP requests in ``mode=sync`` (Sonar S7493).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import anyio


async def read_lines(path: Path) -> AsyncIterator[bytes]:
    """Yield each line of ``path`` with its newline, as bytes."""
    async with await anyio.open_file(path, "rb") as handle:
        async for line in handle:
            yield line
