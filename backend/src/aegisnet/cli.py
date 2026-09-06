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
    create-user EMAIL --role R     create a user; the password is read from stdin
    users                          list users (never hashes)
    create-service-token NAME      mint an ingest service token; the token is printed once
    revoke-service-token TOKEN_ID  revoke a service token
    service-tokens                 list service tokens (never hashes)
    run-detectors --from T --to T  run every detection rule over an interval (sync or async)
    alerts                         list alerts, newest first
    alert ALERT_ID                 show one alert with its sampled events and linked assets
    detector-runs                  recent detector runs
    recompute-baselines            summarise each asset's outbound history into asset_baselines
    baselines                      list the stored baselines
    correlate --from --to          group uncorrelated alerts into incidents
    incidents                      list incidents, newest first
    incident REF                   one incident by case number or id
    eval-correlation               score correlation on the committed multi-stage scenario
    eval-detectors                 score the rules on the labelled cases and the benign corpus;
                                   run inside the checkout, no paths accepted

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
from datetime import datetime, timedelta
from enum import Enum
from ipaddress import ip_address, ip_network
from pathlib import Path, PurePosixPath
from typing import Any, TextIO
from uuid import UUID

import yaml
from pydantic import ValidationError

from aegisnet.adapters.db import engine as db_engine
from aegisnet.adapters.db.asset_store import SqlAssetStore
from aegisnet.adapters.db.audit_store import SqlAuditStore
from aegisnet.adapters.db.auth_store import (
    EmailTakenError,
    ServiceTokenNameTakenError,
    SqlRefreshTokenStore,
    SqlServiceTokenStore,
    SqlUserStore,
)
from aegisnet.adapters.db.detection_store import (
    SqlAlertStore,
    SqlBaselineStore,
    SqlDetectorRunStore,
    SqlRuleStore,
)
from aegisnet.adapters.db.event_read_store import SqlEventReadStore
from aegisnet.adapters.db.incident_store import SqlIncidentStore
from aegisnet.adapters.db.ingest_store import SqlIngestStore
from aegisnet.adapters.db.session import make_session_factory
from aegisnet.adapters.files.labelled import LabelledCaseError
from aegisnet.adapters.files.registry import RegistryError, contained_path, load_registry
from aegisnet.adapters.queue.broker import install as install_broker
from aegisnet.adapters.queue.detection_queue import RedisDetectionQueue
from aegisnet.adapters.queue.ingest_queue import RedisIngestQueue
from aegisnet.config import Settings, get_settings
from aegisnet.domain.assets import AssetError, AssetSpec
from aegisnet.domain.auth import check_password_policy
from aegisnet.domain.enums import AssetEnvironment, EventType, IngestStatus, UserRole
from aegisnet.domain.pagination import DEFAULT_LIMIT, InvalidCursorError
from aegisnet.domain.ports import (
    AlertFilter,
    AssetFilter,
    BatchFilter,
    EventQuery,
    IncidentFilter,
    ServiceTokenRecord,
    UserRecord,
)
from aegisnet.logging import configure_logging
from aegisnet.services.asset_service import AssetService
from aegisnet.services.audit_service import AuditService
from aegisnet.services.auth_service import AuthPolicy, AuthService
from aegisnet.services.baseline_service import BaselineService
from aegisnet.services.correlation_service import (
    CorrelationService,
    summarise,
)
from aegisnet.services.detection_service import (
    AlertNotFoundError,
    DetectionService,
    describe,
    validate_interval,
)
from aegisnet.services.evaluation_service import (
    CASES_DIR,
    CORPUS_FILE,
    RESULTS_DOC,
    EvaluationError,
    render,
    replace_results,
    repository_root,
    run_evaluation,
)
from aegisnet.services.event_read_service import EventQueryError, EventReadService
from aegisnet.services.ingest_service import (
    BatchNotFoundError,
    IngestLimitExceededError,
    IngestService,
    limits_from_settings,
    provenance_for,
)
from aegisnet.services.scenario_service import (
    MANIFEST_FILE,
    SCENARIO_FILE,
    ScenarioEvalError,
    run_scenario,
)
from aegisnet.services.scenario_service import render as render_correlation
from aegisnet.services.scenario_service import replace_results as replace_correlation
from aegisnet.services.scenario_service import repository_root as scenario_root

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_USAGE = 2

ASSETS_DIR = "assets"


class _NoDenylist:
    """The CLI never verifies or revokes access tokens, so it holds no denylist."""

    async def add(self, token_id: str, ttl_seconds: int) -> None:
        raise NotImplementedError("the CLI does not revoke access tokens")

    async def contains(self, token_id: str) -> bool:
        raise NotImplementedError("the CLI does not verify access tokens")


class Services:
    """Every service on one engine, built per command and disposed afterwards."""

    def __init__(self, settings: Settings) -> None:
        self._engine = db_engine.create_engine(settings)
        sessions = make_session_factory(self._engine)
        self.ingest = IngestService(SqlIngestStore(sessions), limits_from_settings(settings))
        asset_store = SqlAssetStore(sessions)
        self.assets = AssetService(asset_store)
        events_store = SqlEventReadStore(sessions)
        self.events = EventReadService(events_store)
        baseline_store = SqlBaselineStore(sessions)
        self.detection = DetectionService(
            SqlRuleStore(sessions),
            SqlDetectorRunStore(sessions),
            SqlAlertStore(sessions),
            events_store,
            self.assets,
            baselines=baseline_store,
        )
        self.baselines = BaselineService(asset_store, events_store, baseline_store)
        self.incidents = SqlIncidentStore(sessions)
        self.correlation = CorrelationService(self.incidents, SqlAlertStore(sessions))
        self.auth = AuthService(
            SqlUserStore(sessions),
            SqlRefreshTokenStore(sessions),
            SqlServiceTokenStore(sessions),
            _NoDenylist(),
            secret=settings.secret_key.get_secret_value(),
            policy=AuthPolicy.from_settings(settings),
        )
        self.audit = AuditService(SqlAuditStore(sessions))

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


def _ttl_days(text: str) -> int:
    try:
        days = int(text)
    except ValueError as error:
        raise argparse.ArgumentTypeError("ttl must be a whole number of days") from error
    if not 1 <= days <= 365:
        raise argparse.ArgumentTypeError("ttl must be between 1 and 365 days")
    return days


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

    create_user = commands.add_parser(
        "create-user", help="create a user; the password is read from stdin, never argv"
    )
    create_user.add_argument("email")
    create_user.add_argument("--role", choices=[r.value for r in UserRole], required=True)
    create_user.add_argument("--display-name", default=None)
    create_user.add_argument(
        "--password-stdin",
        action="store_true",
        required=True,
        help="read the password from the first line of stdin (the only way to supply it)",
    )
    commands.add_parser("users", help="list users (never hashes)")
    token = commands.add_parser(
        "create-service-token", help="mint an ingest service token; printed exactly once"
    )
    token.add_argument("name")
    token.add_argument("--ttl-days", type=_ttl_days, default=90, help="1 to 365, default 90")
    revoke = commands.add_parser("revoke-service-token", help="revoke a service token by id")
    revoke.add_argument("token_id", type=UUID)
    commands.add_parser("service-tokens", help="list service tokens (never hashes)")

    sweep = commands.add_parser("run-detectors", help="run every detection rule over an interval")
    sweep.add_argument("--from", dest="time_from", type=_timestamp, required=True)
    sweep.add_argument("--to", dest="time_to", type=_timestamp, required=True)
    sweep.add_argument("--mode", choices=["sync", "async"], default="sync")
    alerts = commands.add_parser("alerts", help="list alerts, newest first")
    alerts.add_argument("--limit", type=int, default=DEFAULT_LIMIT)
    alerts.add_argument("--severity-min", type=int, default=None, choices=range(1, 6))
    alerts.add_argument("--rule", default=None, help="rule id such as D-001")
    alerts.add_argument("--cursor", default=None)
    alert = commands.add_parser("alert", help="show one alert")
    alert.add_argument("alert_id", type=UUID)
    runs = commands.add_parser("detector-runs", help="recent detector runs, newest first")
    runs.add_argument("--limit", type=int, default=20)
    recompute = commands.add_parser(
        "recompute-baselines", help="summarise each asset's outbound history into asset_baselines"
    )
    recompute.add_argument(
        "--window-days", type=int, default=7, choices=range(1, 91), metavar="1..90"
    )
    recompute.add_argument("--mode", choices=["sync", "async"], default="sync")
    recompute.add_argument(
        "--until",
        dest="until",
        type=_timestamp,
        default=None,
        help="summarise the complete hours before this instant instead of before now; "
        "how a committed scenario is replayed as of the hour it describes (sync only)",
    )
    correlate = commands.add_parser(
        "correlate", help="group uncorrelated alerts in an interval into incidents"
    )
    correlate.add_argument("--from", dest="time_from", type=_timestamp, required=True)
    correlate.add_argument("--to", dest="time_to", type=_timestamp, required=True)

    incidents = commands.add_parser("incidents", help="list incidents, newest first")
    incidents.add_argument(
        "--open", dest="open_only", action="store_true", help="hide closed cases"
    )
    incidents.add_argument("--severity-min", type=int, default=None)
    incidents.add_argument("--limit", type=int, default=DEFAULT_LIMIT)
    incidents.add_argument("--cursor", default=None)

    incident = commands.add_parser("incident", help="show one incident by case number or id")
    incident.add_argument("reference", help="AEG-2026-0001 or a uuid")

    commands.add_parser("baselines", help="list the stored baselines")

    evaluation = commands.add_parser(
        "eval-detectors",
        help="T1/T2 metrics into docs/evaluation.md §8; run inside the checkout, no database",
    )
    evaluation.add_argument(
        "--no-write", action="store_true", help="print the block without touching the document"
    )
    evaluation.add_argument("--json", action="store_true", help="emit the report as JSON")

    correlation = commands.add_parser(
        "eval-correlation",
        help="score correlation on the committed scenario into docs/evaluation.md §8; no database",
    )
    correlation.add_argument(
        "--no-write", action="store_true", help="print the block without touching the document"
    )
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


# ---------------------------------------------------------------- users and service tokens


def public_user(user: UserRecord) -> dict[str, object]:
    """The operator's view of a user: never the password hash."""
    return {
        "id": user.id,
        "email": user.email,
        "display_name": user.display_name,
        "role": user.role,
        "is_active": user.is_active,
        "failed_login_count": user.failed_login_count,
        "locked_until": user.locked_until,
        "last_login_at": user.last_login_at,
        "created_at": user.created_at,
    }


def public_service_token(token: ServiceTokenRecord) -> dict[str, object]:
    """The operator's view of a service token: never the hash."""
    return {
        "id": token.id,
        "name": token.name,
        "role": token.role,
        "created_by": token.created_by,
        "expires_at": token.expires_at,
        "revoked_at": token.revoked_at,
        "last_used_at": token.last_used_at,
        "created_at": token.created_at,
    }


def read_password(stream: TextIO) -> str:
    """The first line of ``stream``, checked against the policy before any connection."""
    password = stream.readline().rstrip("\r\n")
    check_password_policy(password)
    return password


def cmd_create_user(settings: Settings, args: argparse.Namespace) -> int:
    password = read_password(sys.stdin)
    display_name = args.display_name or args.email.split("@")[0]
    role = UserRole(args.role)

    async def action(services: Services) -> UserRecord:
        user = await services.auth.register_user(args.email, display_name, password, role)
        await services.audit.record(
            "user.created",
            target_type="user",
            target_id=str(user.id),
            detail={"role": role.value, "via": "cli"},
        )
        return user

    _emit(public_user(_run(settings, action)))
    return EXIT_OK


def cmd_users(settings: Settings) -> int:
    users = _run(settings, lambda services: services.auth.list_users())
    _emit({"users": [public_user(user) for user in users]})
    return EXIT_OK


def cmd_create_service_token(settings: Settings, args: argparse.Namespace) -> int:
    name = args.name.strip()
    if not 1 <= len(name) <= 64:
        raise ValueError("service token name must be 1 to 64 characters")
    ttl = timedelta(days=args.ttl_days)

    async def action(services: Services) -> tuple[str, ServiceTokenRecord]:
        plaintext, record = await services.auth.create_service_token(name, created_by=None, ttl=ttl)
        await services.audit.record(
            "service_token.created",
            target_type="service_token",
            target_id=str(record.id),
            detail={"name": record.name, "expires_at": record.expires_at.isoformat(), "via": "cli"},
        )
        return plaintext, record

    plaintext, record = _run(settings, action)
    _emit({**public_service_token(record), "token": plaintext})
    return EXIT_OK


def cmd_revoke_service_token(settings: Settings, token_id: UUID) -> int:
    async def action(services: Services) -> ServiceTokenRecord | None:
        record = await services.auth.revoke_service_token(token_id)
        if record is not None:
            await services.audit.record(
                "service_token.revoked",
                target_type="service_token",
                target_id=str(record.id),
                detail={"name": record.name, "via": "cli"},
            )
        return record

    record = _run(settings, action)
    if record is None:
        _emit({"error": "unknown service token"})
        return EXIT_FAILED
    _emit(public_service_token(record))
    return EXIT_OK


def cmd_service_tokens(settings: Settings) -> int:
    tokens = _run(settings, lambda services: services.auth.list_service_tokens())
    _emit({"service_tokens": [public_service_token(token) for token in tokens]})
    return EXIT_OK


# ---------------------------------------------------------------- detection


def cmd_run_detectors(settings: Settings, args: argparse.Namespace) -> int:
    validate_interval(args.time_from, args.time_to)
    if args.mode == "async":
        message_id = RedisDetectionQueue(install_broker(settings)).enqueue_sweep(
            args.time_from, args.time_to
        )
        _emit(
            {
                "queued": True,
                "message_id": message_id,
                "window_start": args.time_from,
                "window_end": args.time_to,
            }
        )
        return EXIT_OK
    outcome = _run(settings, lambda s: s.detection.sweep(args.time_from, args.time_to))
    _emit(describe(outcome))
    return EXIT_FAILED if any(run.status.value == "error" for run in outcome.runs) else EXIT_OK


def cmd_correlate(settings: Settings, args: argparse.Namespace) -> int:
    """Group the uncorrelated alerts in an interval into cases (ADR-023). Re-running an
    interval is a no-op, so this is safe to repeat."""
    outcome = _run(settings, lambda s: s.correlation.correlate(args.time_from, args.time_to))
    _emit(summarise(outcome))
    return EXIT_OK


def cmd_incidents(settings: Settings, args: argparse.Namespace) -> int:
    query = IncidentFilter(
        open_only=args.open_only,
        severity_min=args.severity_min,
        limit=args.limit,
        cursor=args.cursor,
    )
    page = _run(settings, lambda s: s.incidents.list(query))
    _emit({"incidents": list(page.items), "next_cursor": page.next_cursor})
    return EXIT_OK


def cmd_incident(settings: Settings, reference: str) -> int:
    """One case by number (`AEG-2026-0001`) or by id, with its alerts and its timeline."""

    async def lookup(services: Services) -> object:
        try:
            incident_id = UUID(reference)
        except ValueError:
            return await services.incidents.get_by_case_number(reference)
        return await services.incidents.get(incident_id)

    detail = _run(settings, lookup)
    if detail is None:
        _emit({"error": f"no incident {reference}"})
        return EXIT_FAILED
    _emit(detail)
    return EXIT_OK


def cmd_alerts(settings: Settings, args: argparse.Namespace) -> int:
    query = AlertFilter(
        severity_min=args.severity_min, rule_id=args.rule, limit=args.limit, cursor=args.cursor
    )
    page = _run(settings, lambda s: s.detection.list_alerts(query))
    _emit({"alerts": list(page.items), "next_cursor": page.next_cursor})
    return EXIT_OK


def cmd_alert(settings: Settings, alert_id: UUID) -> int:
    detail = _run(settings, lambda s: s.detection.get_alert(alert_id))
    _emit(
        {
            "alert": detail.alert,
            "events": [{"event_id": e, "role": r} for e, r in detail.events],
            "assets": [{"asset_id": a, "role": r} for a, r in detail.assets],
        }
    )
    return EXIT_OK


def cmd_detector_runs(settings: Settings, limit: int) -> int:
    runs = _run(settings, lambda s: s.detection.list_runs(limit=limit))
    _emit({"runs": list(runs)})
    return EXIT_OK


def cmd_recompute_baselines(settings: Settings, args: argparse.Namespace) -> int:
    if args.mode == "async":
        if args.until is not None:
            # The queued actor takes a window in days and nothing else. Accepting `--until`
            # here and dropping it would compute a baseline over the wrong week and say
            # nothing about it.
            _emit({"error": "--until is only available with --mode sync"})
            return EXIT_FAILED
        message_id = RedisDetectionQueue(install_broker(settings)).enqueue_baselines(
            args.window_days
        )
        _emit({"queued": True, "message_id": message_id, "window_days": args.window_days})
        return EXIT_OK

    async def action(services: Services) -> object:
        service = BaselineService(
            services.baselines._assets,
            services.baselines._history,
            services.baselines._baselines,
            window_days=args.window_days,
        )
        return await service.recompute(until=args.until)

    _emit(_run(settings, action))
    return EXIT_OK


def cmd_baselines(settings: Settings) -> int:
    rows = _run(settings, lambda s: s.baselines.list())
    _emit({"baselines": list(rows)})
    return EXIT_OK


# ---------------------------------------------------------------- entrypoint


def cmd_eval(args: argparse.Namespace) -> int:
    """No path is accepted: the cases, the corpus and the document sit at fixed places under
    the repository root found above the working directory. Exit 1 when a labelled case
    misses its label, after writing the report anyway: the document must show the
    regression, not hide it."""
    try:
        root = repository_root(Path.cwd())
        report = run_evaluation(root / CASES_DIR, root / CORPUS_FILE)
        block = render(report)
        if not args.no_write:
            document = root / RESULTS_DOC
            document.write_text(
                replace_results(document.read_text(encoding="utf-8"), block), encoding="utf-8"
            )
    except (EvaluationError, LabelledCaseError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)  # noqa: T201 - CLI output
        return 1
    if args.json:
        _emit(
            {
                "metrics": list(report.metrics),
                "failures": [
                    {"case_id": o.expectation.case_id, "verdict": o.verdict, "reason": o.reason}
                    for o in report.failures
                ],
                "corpus": {
                    "name": report.corpus_name,
                    "sha256": report.corpus_sha256,
                    "events": report.corpus_events,
                    "rejected": report.corpus_rejected,
                },
            }
        )
    else:
        print(block)  # noqa: T201 - CLI output
    return 1 if report.failures else 0


def cmd_eval_correlation(args: argparse.Namespace) -> int:
    """Score the committed scenario's grouping and refresh §8's correlation block.

    Like `eval-detectors`, this takes no path and needs no database: the scenario, its ground
    truth and the document are fixed names under the repository root found above the working
    directory.
    """
    try:
        root = scenario_root(Path.cwd())
        report = run_scenario(root / SCENARIO_FILE, root / MANIFEST_FILE)
        block = render_correlation(report)
        if not args.no_write:
            document = root / RESULTS_DOC
            document.write_text(
                replace_correlation(document.read_text(encoding="utf-8"), block), encoding="utf-8"
            )
    except (ScenarioEvalError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)  # noqa: T201 - CLI output
        return EXIT_FAILED
    print(block)  # noqa: T201 - CLI output
    return EXIT_OK


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
        case "create-user":
            return cmd_create_user(settings, args)
        case "users":
            return cmd_users(settings)
        case "create-service-token":
            return cmd_create_service_token(settings, args)
        case "revoke-service-token":
            return cmd_revoke_service_token(settings, args.token_id)
        case "service-tokens":
            return cmd_service_tokens(settings)
        case "run-detectors":
            return cmd_run_detectors(settings, args)
        case "alerts":
            return cmd_alerts(settings, args)
        case "alert":
            return cmd_alert(settings, args.alert_id)
        case "detector-runs":
            return cmd_detector_runs(settings, args.limit)
        case "recompute-baselines":
            return cmd_recompute_baselines(settings, args)
        case "correlate":
            return cmd_correlate(settings, args)
        case "incidents":
            return cmd_incidents(settings, args)
        case "incident":
            return cmd_incident(settings, args.reference)
        case "baselines":
            return cmd_baselines(settings)
    return EXIT_USAGE  # pragma: no cover - argparse enforces the command set


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "eval-correlation":
        return cmd_eval_correlation(args)
    if args.command == "eval-detectors":
        # Files in, files out: no database, no broker, so no secrets are demanded either.
        return cmd_eval(args)
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
        EmailTakenError,
        ServiceTokenNameTakenError,
        AlertNotFoundError,
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
