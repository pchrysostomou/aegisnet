"""FastAPI application factory.

Assembles configuration, structured logging, correlation-ID propagation, the error
envelope, the routers, and the services every route depends on. The services are built
by a factory so tests can install in-memory ports while the routes stay identical.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from datetime import datetime
from typing import Protocol
from uuid import UUID

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncEngine

from aegisnet.adapters.cache import redis_client
from aegisnet.adapters.cache.rate_limiter import RedisRateLimiter, RedisTokenDenylist
from aegisnet.adapters.db import engine as db_engine
from aegisnet.adapters.db.asset_store import SqlAssetStore
from aegisnet.adapters.db.audit_store import SqlAuditStore
from aegisnet.adapters.db.auth_store import (
    SqlRefreshTokenStore,
    SqlServiceTokenStore,
    SqlUserStore,
)
from aegisnet.adapters.db.brief_store import SqlBriefStore
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
from aegisnet.adapters.files.spool import Spool
from aegisnet.adapters.perplexity import PerplexityClient, RedisDailyBudget
from aegisnet.adapters.queue.broker import install as install_broker
from aegisnet.adapters.queue.detection_queue import RedisDetectionQueue
from aegisnet.adapters.queue.ingest_queue import RedisIngestQueue
from aegisnet.api.deps import AppServices
from aegisnet.api.errors import register_error_handlers
from aegisnet.api.v1 import (
    alerts,
    assets,
    audit,
    auth,
    briefs,
    detections,
    events,
    health,
    incidents,
    ingest,
    meta,
    reports,
)
from aegisnet.config import Settings, get_settings
from aegisnet.logging import configure_logging, correlation_id_var, get_logger
from aegisnet.services.asset_service import AssetService
from aegisnet.services.audit_service import AuditReadService, AuditService
from aegisnet.services.auth_service import AuthPolicy, AuthService
from aegisnet.services.baseline_service import BaselineService
from aegisnet.services.brief_service import BriefService
from aegisnet.services.detection_service import DetectionService
from aegisnet.services.event_read_service import EventReadService
from aegisnet.services.incident_service import IncidentService
from aegisnet.services.ingest_service import IngestService, limits_from_settings
from aegisnet.services.report_service import ReportService
from aegisnet.version import APP_VERSION

logger = get_logger(__name__)

CORRELATION_HEADER = "X-Correlation-ID"


class ServicesFactory(Protocol):
    def __call__(self, settings: Settings, engine: AsyncEngine, cache: Redis) -> AppServices: ...


def build_services(settings: Settings, engine: AsyncEngine, cache: Redis) -> AppServices:
    """Production wiring: SQL stores, the Redis limiter and denylist, the Dramatiq broker."""
    sessions = make_session_factory(engine)
    audit_store = SqlAuditStore(sessions)
    broker = install_broker(settings)
    queue = RedisIngestQueue(broker)
    detection_queue = RedisDetectionQueue(broker)
    events_store = SqlEventReadStore(sessions)
    asset_store = SqlAssetStore(sessions)
    asset_service = AssetService(asset_store)
    baseline_store = SqlBaselineStore(sessions)
    incident_store = SqlIncidentStore(sessions)
    brief_store = SqlBriefStore(sessions)
    alert_store = SqlAlertStore(sessions)
    ingest_store = SqlIngestStore(sessions)

    async def enqueue_upload(batch_id: UUID, spool_name: str, source_label: str) -> str:
        return queue.enqueue_upload(batch_id, spool_name, source_label)

    async def enqueue_import(batch_id: UUID, dataset_id: str, source_label: str) -> str:
        return queue.enqueue_import(batch_id, dataset_id, source_label)

    async def enqueue_sweep(start: datetime, end: datetime) -> str:
        return detection_queue.enqueue_sweep(start, end)

    async def enqueue_baselines(window_days: int) -> str:
        return detection_queue.enqueue_baselines(window_days)

    return AppServices(
        settings=settings,
        auth=AuthService(
            SqlUserStore(sessions),
            SqlRefreshTokenStore(sessions),
            SqlServiceTokenStore(sessions),
            RedisTokenDenylist(cache),
            secret=settings.secret_key.get_secret_value(),
            policy=AuthPolicy.from_settings(settings),
        ),
        audit=AuditService(audit_store),
        audit_read=AuditReadService(audit_store),
        ingest=IngestService(ingest_store, limits_from_settings(settings)),
        assets=asset_service,
        events=EventReadService(events_store),
        limiter=RedisRateLimiter(cache),
        spool=Spool(settings.spool_dir),
        enqueue_upload=enqueue_upload,
        enqueue_import=enqueue_import,
        detection=DetectionService(
            SqlRuleStore(sessions),
            SqlDetectorRunStore(sessions),
            alert_store,
            events_store,
            asset_service,
            baselines=baseline_store,
        ),
        enqueue_sweep=enqueue_sweep,
        baselines=BaselineService(asset_store, events_store, baseline_store),
        enqueue_baselines=enqueue_baselines,
        incidents=IncidentService(incident_store),
        reports=ReportService(
            incident_store,
            brief_store,
            alerts=alert_store,
            events=events_store,
            ingest=ingest_store,
            assets=asset_service,
        ),
        briefs=BriefService(
            incident_store,
            brief_store,
            PerplexityClient(
                settings,
                # The cap is shared with the worker and the CLI rather than counted here.
                budget=RedisDailyBudget(cache, settings.brief_daily_budget),
            ),
            samples_dir=settings.samples_dir,
        ),
    )


def _lifespan(
    services_factory: ServicesFactory,
) -> Callable[[FastAPI], AbstractAsyncContextManager[None]]:
    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        settings: Settings = app.state.settings
        engine = db_engine.create_api_engine(settings)
        cache = redis_client.create_client(settings)
        app.state.db_engine = engine
        app.state.redis = cache
        # Readiness is defined as exactly these dependencies.
        app.state.readiness_probes = {
            "postgres": lambda: db_engine.ping(engine),
            "redis": lambda: redis_client.ping(cache),
        }
        app.state.services = services_factory(settings, engine, cache)
        app.state.services.spool.ensure_writable()
        logger.info(
            "application_started",
            extra={
                "version": APP_VERSION,
                "environment": str(settings.env),
                "readiness_components": ["postgres", "redis"],
            },
        )
        try:
            yield
        finally:
            await db_engine.dispose(engine)
            await redis_client.close(cache)
            logger.info("application_stopped")

    return lifespan


def canonical_correlation_id(supplied: str) -> str:
    """Return the inbound id in canonical UUID form, or a fresh id if it is not a UUID.

    The echoed value is never the inbound string: the header is parsed to a UUID, reduced
    to its 128-bit integer, and a new UUID is rendered from that integer. Only the number
    survives the round trip, so no request-derived text reaches the response header or the
    log context, and a canonical UUID cannot carry CR, LF or any other control character.
    """
    try:
        parsed = uuid.UUID(supplied)
    except (ValueError, AttributeError, TypeError):
        return str(uuid.uuid4())
    return str(uuid.UUID(int=int(parsed.int)))


def _install_correlation_middleware(app: FastAPI) -> None:
    @app.middleware("http")
    async def correlation_middleware(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        # An inbound header is accepted for tracing but never trusted as content: it is
        # replaced unless it is a well-formed UUID.
        correlation_id = canonical_correlation_id(request.headers.get(CORRELATION_HEADER, ""))

        token = correlation_id_var.set(correlation_id)
        try:
            response = await call_next(request)
        finally:
            correlation_id_var.reset(token)
        response.headers[CORRELATION_HEADER] = correlation_id
        return response


def create_app(
    settings: Settings | None = None, *, services_factory: ServicesFactory = build_services
) -> FastAPI:
    resolved = settings or get_settings()
    configure_logging(level=resolved.log_level, secrets=resolved.secret_values())

    app = FastAPI(
        title="AegisNet API",
        version=APP_VERSION,
        summary="Defensive network threat detection lab",
        # Interactive docs are disabled in production (THREAT_MODEL T-2.7).
        docs_url=None if resolved.is_production else "/docs",
        redoc_url=None,
        openapi_url=None if resolved.is_production else "/openapi.json",
        lifespan=_lifespan(services_factory),
    )
    app.state.settings = resolved

    _install_correlation_middleware(app)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=resolved.cors_origin_list,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type", "X-Ingest-Token", CORRELATION_HEADER],
    )

    register_error_handlers(app)
    app.include_router(health.router)
    app.include_router(meta.router)
    app.include_router(auth.router)
    app.include_router(ingest.router)
    app.include_router(assets.router)
    app.include_router(events.router)
    app.include_router(audit.router)
    app.include_router(alerts.router)
    app.include_router(detections.router)
    app.include_router(incidents.router)
    app.include_router(briefs.router)
    app.include_router(reports.router)
    return app


app = create_app()
