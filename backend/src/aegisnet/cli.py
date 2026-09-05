"""Operator CLI: ``python -m aegisnet.cli <command>``.

Until the HTTP routes ship with authentication in Chunk 6 (ADR-014), this is the
operator's surface for ingest and the asset inventory. Inside the stack:

    docker compose run --rm api python -m aegisnet.cli <command> ...

Commands:
    datasets                       list the ids in samples/registry.yml
    import-dataset ID              ingest a registered dataset, sync (default) or async
    batch BATCH_ID                 show one batch's status and counts
    batches                        list batches, newest first
    rejects BATCH_ID               list a batch's rejected lines
    seed-assets NAME               upsert assets from samples/assets/NAME.yml by hostname
    assets                         list assets (--all includes deactivated ones)
    asset ASSET_ID                 show one asset
    resolve IP                     the asset owning an address, or {"matched": false}
    events --from T --to T         query events (filters, keyset pagination, --payload)
    event-stats --from T --to T    counts by type and by hour

Every result is one JSON object on stdout; exit status 0 on success, 1 on a failure the
operator can act on (failed batch, registry or inventory error), 2 on usage errors.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from collections.abc import Callable, Coroutine, Sequence
from dataclasses import asdict, is_dataclass
from datetime import datetime
from enum import Enum
from ipaddress import ip_address, ip_network
from pathlib import Path, PurePosixPath
from typing import Any
from uuid import UUID

import yaml
from pydantic import ValidationError

from aegisnet.adapters.db import engine as db_engine
from aegisnet.adapters.db.asset_store import SqlAssetStore
from aegisnet.adapters.db.event_read_store import SqlEventReadStore
from aegisnet.adapters.db.ingest_store import SqlIngestStore
from aegisnet.adapters.db.session import make_session_factory
from aegisnet.adapters.files.registry import RegistryError, contained_path, load_registry
from aegisnet.adapters.queue.broker import install as install_broker
from aegisnet.adapters.queue.ingest_queue import RedisIngestQueue
from aegisnet.config import Settings, get_settings
from aegisnet.domain.assets import AssetError, AssetSpec
from aegisnet.domain.enums import AssetEnvironment, EventType, IngestStatus
from aegisnet.domain.pagination import DEFAULT_LIMIT, InvalidCursorError
from aegisnet.domain.ports import AssetFilter, BatchFilter, EventQuery
from aegisnet.logging import configure_logging
from aegisnet.services.asset_service import AssetService
from aegisnet.services.event_read_service import EventQueryError, EventReadService
from aegisnet.services.ingest_service import (
    BatchNotFoundError,
    IngestLimitExceededError,
    IngestService,
    limits_from_settings,
    provenance_for,
)

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_USAGE = 2

ASSETS_DIR = "assets"


class Services:
    """Every service on one engine, built per command and disposed afterwards."""

    def __init__(self, settings: Settings) -> None:
        self._engine = db_engine.create_engine(settings)
        sessions = make_session_factory(self._engine)
        self.ingest = IngestService(SqlIngestStore(sessions), limits_from_settings(settings))
        self.assets = AssetService(SqlAssetStore(sessions))
        self.events = EventReadService(SqlEventReadStore(sessions))

    async def dispose(self) -> None:
        await db_engine.dispose(self._engine)


def _plain(value: object) -> object:
    """Dataclasses become dicts, enums their values, dates ISO strings, the rest strings."""
    if is_dataclass(value) and not isinstance(value, type):
        return {key: _plain(item) for key, item in asdict(value).items()}
    if isinstance(value, dict):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [_plain(item) for item in value]
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, bytes):
        return value.hex()
    if value is None or isinstance(value, str | int | float | bool):
        return value
    return str(value)


def _emit(payload: object) -> None:
    print(json.dumps(_plain(payload), sort_keys=True))  # noqa: T201 - CLI output


def _timestamp(text: str) -> datetime:
    moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if moment.tzinfo is None:
        raise argparse.ArgumentTypeError("timestamps must carry a UTC offset, e.g. ...Z")
    return moment


def _ip_or_cidr(text: str) -> Any:
    try:
        return ip_network(text, strict=True) if "/" in text else ip_address(text)
    except ValueError as error:
        raise argparse.ArgumentTypeError(str(error)) from error


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aegisnet", description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--samples-dir",
        type=Path,
        default=None,
        help="override SAMPLES_DIR (the directory holding registry.yml and assets/)",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser("datasets", help="list registered dataset ids")

    importer = commands.add_parser("import-dataset", help="ingest a registered dataset")
    importer.add_argument("dataset_id")
    importer.add_argument("--source-label", required=True, help="provenance label, 1-64 chars")
    importer.add_argument("--mode", choices=("sync", "async"), default="sync")

    batch = commands.add_parser("batch", help="show a batch by id")
    batch.add_argument("batch_id", type=UUID)

    batches = commands.add_parser("batches", help="list batches, newest first")
    batches.add_argument("--status", choices=[s.value for s in IngestStatus], default=None)
    batches.add_argument("--source-label", default=None)
    batches.add_argument("--limit", type=int, default=DEFAULT_LIMIT)
    batches.add_argument("--cursor", default=None)

    rejects = commands.add_parser("rejects", help="list a batch's rejected lines")
    rejects.add_argument("batch_id", type=UUID)
    rejects.add_argument("--limit", type=int, default=DEFAULT_LIMIT)
    rejects.add_argument("--cursor", default=None)

    seed = commands.add_parser("seed-assets", help="upsert assets from samples/assets/NAME.yml")
    seed.add_argument("name", help="file name without extension, [a-z0-9-_]")

    assets = commands.add_parser("assets", help="list assets")
    assets.add_argument("--environment", choices=[e.value for e in AssetEnvironment])
    assets.add_argument("--criticality-min", type=int, default=None)
    assets.add_argument("--tag", default=None)
    assets.add_argument("-q", "--query", default=None, help="hostname substring")
    assets.add_argument("--all", action="store_true", help="include deactivated assets")
    assets.add_argument("--limit", type=int, default=DEFAULT_LIMIT)
    assets.add_argument("--cursor", default=None)

    asset = commands.add_parser("asset", help="show one asset")
    asset.add_argument("asset_id", type=UUID)

    resolve = commands.add_parser("resolve", help="find the asset owning an address")
    resolve.add_argument("ip", type=ip_address)

    events = commands.add_parser("events", help="query events in a time window")
    events.add_argument("--from", dest="time_from", type=_timestamp, required=True)
    events.add_argument("--to", dest="time_to", type=_timestamp, required=True)
    events.add_argument(
        "--type",
        dest="types",
        action="append",
        default=[],
        choices=[t.value for t in EventType],
        help="repeatable",
    )
    events.add_argument("--src-ip", type=_ip_or_cidr, default=None, help="address or CIDR")
    events.add_argument("--dest-ip", type=_ip_or_cidr, default=None, help="address or CIDR")
    events.add_argument("--dest-port", dest="dest_ports", type=int, action="append", default=[])
    events.add_argument("--flow-id", type=int, default=None)
    events.add_argument("--batch-id", type=UUID, default=None)
    events.add_argument("--asset-id", type=UUID, default=None)
    events.add_argument("--limit", type=int, default=DEFAULT_LIMIT)
    events.add_argument("--cursor", default=None)
    events.add_argument("--payload", action="store_true", help="include the full payload")

    stats = commands.add_parser("event-stats", help="counts by type and by hour")
    stats.add_argument("--from", dest="time_from", type=_timestamp, required=True)
    stats.add_argument("--to", dest="time_to", type=_timestamp, required=True)
    stats.add_argument(
        "--type", dest="types", action="append", default=[], choices=[t.value for t in EventType]
    )
    stats.add_argument("--asset-id", type=UUID, default=None)
    return parser


def _run(settings: Settings, action: Callable[[Services], Coroutine[Any, Any, Any]]) -> Any:
    async def wrapped() -> Any:
        services = Services(settings)
        try:
            return await action(services)
        finally:
            await services.dispose()

    return asyncio.run(wrapped())


# ---------------------------------------------------------------- datasets and batches


def cmd_datasets(samples_dir: Path) -> int:
    registry = load_registry(samples_dir)
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

    async def run_sync(services: Services) -> Any:
        return await services.ingest.import_dataset(
            samples_dir, args.dataset_id, source_label=label
        )

    async def run_async(services: Services) -> dict[str, Any]:
        resolved = services.ingest.resolve(samples_dir, args.dataset_id)
        batch_id = await services.ingest.open_batch(provenance_for(resolved, label))
        queue = RedisIngestQueue(install_broker(settings))
        message_id = queue.enqueue_import(batch_id, args.dataset_id, label)
        return {"batch_id": batch_id, "status": "received", "message_id": message_id}

    if args.mode == "sync":
        summary = _run(settings, run_sync)
        _emit(summary)
        return EXIT_OK if summary.status is IngestStatus.complete else EXIT_FAILED
    _emit(_run(settings, run_async))
    return EXIT_OK


def cmd_batch(settings: Settings, batch_id: UUID) -> int:
    summary = _run(settings, lambda s: s.ingest.get_batch(batch_id))
    if summary is None:
        _emit({"error": "unknown batch"})
        return EXIT_FAILED
    _emit(summary)
    return EXIT_OK


def cmd_batches(settings: Settings, args: argparse.Namespace) -> int:
    query = BatchFilter(
        status=IngestStatus(args.status) if args.status else None,
        source_label=args.source_label,
        limit=args.limit,
        cursor=args.cursor,
    )
    _emit(_run(settings, lambda s: s.ingest.list_batches(query)))
    return EXIT_OK


def cmd_rejects(settings: Settings, args: argparse.Namespace) -> int:
    _emit(
        _run(
            settings,
            lambda s: s.ingest.list_rejects(args.batch_id, limit=args.limit, cursor=args.cursor),
        )
    )
    return EXIT_OK


# ---------------------------------------------------------------- assets


def load_seed_file(samples_dir: Path, name: str) -> list[AssetSpec]:
    """``samples/assets/<name>.yml``: a mapping with an ``assets`` list of asset specs.
    The path is confined to the samples directory exactly like a dataset (T-1.6)."""
    if not name or not all(ch.isalnum() or ch in "-_" for ch in name):
        raise ValueError("seed name must match [A-Za-z0-9_-]+")
    path = contained_path(samples_dir, str(PurePosixPath(ASSETS_DIR) / f"{name}.yml"))
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or not isinstance(raw.get("assets"), list):
        raise ValueError("seed file must be a mapping with an 'assets' list")
    return [AssetSpec.model_validate(item) for item in raw["assets"]]


def cmd_seed(settings: Settings, samples_dir: Path, name: str) -> int:
    specs = load_seed_file(samples_dir, name)
    result = _run(settings, lambda s: s.assets.seed(specs))
    _emit(
        {"seed": name, "assets": len(specs), "created": result.created, "updated": result.updated}
    )
    return EXIT_OK


def cmd_assets(settings: Settings, args: argparse.Namespace) -> int:
    query = AssetFilter(
        environment=AssetEnvironment(args.environment) if args.environment else None,
        criticality_min=args.criticality_min,
        tag=args.tag,
        q=args.query,
        include_inactive=args.all,
        limit=args.limit,
        cursor=args.cursor,
    )
    _emit(_run(settings, lambda s: s.assets.list(query)))
    return EXIT_OK


def cmd_asset(settings: Settings, asset_id: UUID) -> int:
    _emit(_run(settings, lambda s: s.assets.get(asset_id)))
    return EXIT_OK


def cmd_resolve(settings: Settings, address: Any) -> int:
    resolved = _run(settings, lambda s: s.assets.resolve(address))
    if resolved is None:
        _emit({"matched": False, "ip": str(address)})
    else:
        _emit({"matched": True, "ip": str(address), "resolved": resolved})
    return EXIT_OK


# ---------------------------------------------------------------- events


def _event_query(args: argparse.Namespace, *, include_payload: bool) -> EventQuery:
    return EventQuery(
        time_from=args.time_from,
        time_to=args.time_to,
        event_types=tuple(EventType(kind) for kind in args.types),
        src_ip=getattr(args, "src_ip", None),
        dest_ip=getattr(args, "dest_ip", None),
        dest_ports=tuple(getattr(args, "dest_ports", ())),
        flow_id=getattr(args, "flow_id", None),
        batch_id=getattr(args, "batch_id", None),
        asset_id=args.asset_id,
        limit=getattr(args, "limit", DEFAULT_LIMIT),
        cursor=getattr(args, "cursor", None),
        include_payload=include_payload,
    )


def cmd_events(settings: Settings, args: argparse.Namespace) -> int:
    query = _event_query(args, include_payload=args.payload)
    _emit(_run(settings, lambda s: s.events.query(query)))
    return EXIT_OK


def cmd_event_stats(settings: Settings, args: argparse.Namespace) -> int:
    query = _event_query(args, include_payload=False)
    _emit(_run(settings, lambda s: s.events.stats(query)))
    return EXIT_OK


# ---------------------------------------------------------------- entrypoint


def dispatch(settings: Settings, samples_dir: Path, args: argparse.Namespace) -> int:
    match args.command:
        case "datasets":
            return cmd_datasets(samples_dir)
        case "import-dataset":
            return cmd_import(settings, samples_dir, args)
        case "batch":
            return cmd_batch(settings, args.batch_id)
        case "batches":
            return cmd_batches(settings, args)
        case "rejects":
            return cmd_rejects(settings, args)
        case "seed-assets":
            return cmd_seed(settings, samples_dir, args.name)
        case "assets":
            return cmd_assets(settings, args)
        case "asset":
            return cmd_asset(settings, args.asset_id)
        case "resolve":
            return cmd_resolve(settings, args.ip)
        case "events":
            return cmd_events(settings, args)
        case "event-stats":
            return cmd_event_stats(settings, args)
    return EXIT_USAGE  # pragma: no cover - argparse enforces the command set


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    settings = get_settings()
    configure_logging(level=settings.log_level, secrets=settings.secret_values())
    samples_dir = args.samples_dir or settings.samples_dir
    try:
        return dispatch(settings, samples_dir, args)
    except (
        RegistryError,
        IngestLimitExceededError,
        BatchNotFoundError,
        AssetError,
        EventQueryError,
        InvalidCursorError,
    ) as error:
        _emit({"error": str(error)})
        return EXIT_FAILED
    except ValidationError as error:
        _emit({"error": "invalid input", "details": error.errors(include_url=False)})
        return EXIT_USAGE
    except ValueError as error:
        _emit({"error": str(error)})
        return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())
