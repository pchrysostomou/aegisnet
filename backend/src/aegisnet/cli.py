"""Operator CLI: ``python -m aegisnet.cli <command>``.

Chunk 4 exposes ingest here rather than over HTTP, because the HTTP surface must not ship
without the authentication and RBAC dependencies of Chunk 6 (ADR-014). Inside the stack:

    docker compose run --rm api python -m aegisnet.cli import-dataset <id> --source-label x

Commands:
    datasets                       list the ids in samples/registry.yml
    import-dataset ID              ingest a registered dataset, sync (default) or async
    batch BATCH_ID                 show one batch's status and counts

Every result is one JSON object on stdout; exit status 0 on success, 1 on a failed batch
or registry error, 2 on usage errors.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from collections.abc import Sequence
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import UUID

from aegisnet.adapters.db import engine as db_engine
from aegisnet.adapters.db.ingest_store import SqlIngestStore
from aegisnet.adapters.db.session import make_session_factory
from aegisnet.adapters.files.registry import RegistryError, load_registry
from aegisnet.adapters.queue.broker import install as install_broker
from aegisnet.adapters.queue.ingest_queue import RedisIngestQueue
from aegisnet.config import Settings, get_settings
from aegisnet.domain.ports import BatchSummary
from aegisnet.logging import configure_logging
from aegisnet.services.ingest_service import (
    IngestLimitExceededError,
    IngestService,
    limits_from_settings,
    provenance_for,
)

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_USAGE = 2


def _emit(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, default=_json_default, sort_keys=True))  # noqa: T201 - CLI output


def _json_default(value: object) -> str:
    if isinstance(value, datetime | UUID):
        return str(value) if isinstance(value, UUID) else value.isoformat()
    raise TypeError(f"not serialisable: {type(value).__name__}")


def _summary_payload(summary: BatchSummary) -> dict[str, Any]:
    payload = asdict(summary)
    payload["status"] = summary.status.value
    return payload


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aegisnet", description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--samples-dir",
        type=Path,
        default=None,
        help="override SAMPLES_DIR (the directory holding registry.yml)",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser("datasets", help="list registered dataset ids")

    importer = commands.add_parser("import-dataset", help="ingest a registered dataset")
    importer.add_argument("dataset_id")
    importer.add_argument("--source-label", required=True, help="provenance label, 1-64 chars")
    importer.add_argument(
        "--mode",
        choices=("sync", "async"),
        default="sync",
        help="sync: run here and print the finished batch; async: enqueue for the worker",
    )

    batch = commands.add_parser("batch", help="show a batch by id")
    batch.add_argument("batch_id", type=UUID)
    return parser


async def _with_service(
    settings: Settings, run: Any
) -> Any:  # pragma: no cover - thin wiring exercised by the database suite
    engine = db_engine.create_engine(settings)
    try:
        service = IngestService(
            SqlIngestStore(make_session_factory(engine)), limits_from_settings(settings)
        )
        return await run(service)
    finally:
        await db_engine.dispose(engine)


def cmd_datasets(samples_dir: Path) -> int:
    try:
        registry = load_registry(samples_dir)
    except RegistryError as error:
        _emit({"error": str(error)})
        return EXIT_FAILED
    _emit(
        {
            "datasets": [
                {
                    "id": entry.id,
                    "format": entry.format,
                    "licence": entry.licence,
                    "citation": entry.citation,
                    "description": entry.description,
                }
                for entry in registry.datasets
            ]
        }
    )
    return EXIT_OK


def cmd_import(settings: Settings, samples_dir: Path, args: argparse.Namespace) -> int:
    label = args.source_label
    if not 1 <= len(label) <= 64:
        _emit({"error": "--source-label must be 1 to 64 characters"})
        return EXIT_USAGE

    async def run_sync(service: IngestService) -> BatchSummary:
        return await service.import_dataset(samples_dir, args.dataset_id, source_label=label)

    async def run_async(service: IngestService) -> dict[str, Any]:
        resolved = service.resolve(samples_dir, args.dataset_id)
        batch_id = await service.open_batch(provenance_for(resolved, label))
        queue = RedisIngestQueue(install_broker(settings))
        message_id = queue.enqueue_import(batch_id, args.dataset_id, label)
        return {"batch_id": batch_id, "status": "received", "message_id": message_id}

    try:
        if args.mode == "sync":
            summary = asyncio.run(_with_service(settings, run_sync))
            _emit(_summary_payload(summary))
            return EXIT_OK if summary.status.value == "complete" else EXIT_FAILED
        _emit(asyncio.run(_with_service(settings, run_async)))
        return EXIT_OK
    except RegistryError as error:
        _emit({"error": str(error)})
        return EXIT_FAILED
    except IngestLimitExceededError as error:
        _emit({"error": str(error)})
        return EXIT_FAILED


def cmd_batch(settings: Settings, batch_id: UUID) -> int:
    async def run(service: IngestService) -> BatchSummary | None:
        return await service.get_batch(batch_id)

    summary = asyncio.run(_with_service(settings, run))
    if summary is None:
        _emit({"error": "unknown batch"})
        return EXIT_FAILED
    _emit(_summary_payload(summary))
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    settings = get_settings()
    configure_logging(level=settings.log_level, secrets=settings.secret_values())
    samples_dir = args.samples_dir or settings.samples_dir
    if args.command == "datasets":
        return cmd_datasets(samples_dir)
    if args.command == "import-dataset":
        return cmd_import(settings, samples_dir, args)
    return cmd_batch(settings, args.batch_id)


if __name__ == "__main__":
    sys.exit(main())
