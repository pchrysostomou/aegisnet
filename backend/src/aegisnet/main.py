"""FastAPI application factory.

Chunk 1 assembles: configuration, structured logging, correlation-ID propagation,
the global error envelope, health/readiness/version routes, and connectivity adapters
for PostgreSQL and Redis.

Nothing else is wired. There is no database session dependency, no authentication, no
rate limiting, and no ingestion route — see docs/STATUS.md for the honest scope.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware

from aegisnet.adapters.cache import redis_client
from aegisnet.adapters.db import engine as db_engine
from aegisnet.api.errors import register_error_handlers
from aegisnet.api.v1 import health, meta
from aegisnet.config import Settings, get_settings
from aegisnet.logging import configure_logging, correlation_id_var, get_logger, untrusted_text
from aegisnet.version import APP_VERSION

logger = get_logger(__name__)

CORRELATION_HEADER = "X-Correlation-ID"


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings: Settings = app.state.settings
    engine = db_engine.create_engine(settings)
    cache = redis_client.create_client(settings)

    app.state.db_engine = engine
    app.state.redis = cache
    # Readiness is defined as exactly these dependencies in Chunk 1.
    app.state.readiness_probes = {
        "postgres": lambda: db_engine.ping(engine),
        "redis": lambda: redis_client.ping(cache),
    }

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


def canonical_correlation_id(supplied: str) -> str:
    """Return the inbound id in canonical UUID form, or a fresh id if it is not a UUID.

    The value is re-rendered from the parsed UUID and then passed through the same CR/LF
    strip as every other request-derived string before it is echoed in a response header.
    A canonical UUID cannot contain those characters, so the strip changes nothing; it
    keeps the header-injection guard explicit at the sink rather than implied by the
    parser.
    """
    try:
        parsed = uuid.UUID(supplied)
    except (ValueError, AttributeError, TypeError):
        return str(uuid.uuid4())
    return untrusted_text(str(parsed), max_chars=36)


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


def create_app(settings: Settings | None = None) -> FastAPI:
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
        lifespan=lifespan,
    )
    app.state.settings = resolved

    _install_correlation_middleware(app)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=resolved.cors_origin_list,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type", CORRELATION_HEADER],
    )

    register_error_handlers(app)
    app.include_router(health.router)
    app.include_router(meta.router)
    return app


app = create_app()
