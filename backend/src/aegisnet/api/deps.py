"""Request-scoped dependencies: services, the calling principal, permissions, rate limits.

Every non-health route declares exactly one permission through :func:`require`; the
route-enumeration test fails the build if one does not. ``require`` audits denials as
``rbac.denied``. Rate limits are keyed by the principal's subject (or the client address
before authentication) and fail *closed* for login and ingest, *open* for reads, so a
Redis outage cannot open the write paths or close the whole read surface.
"""

from __future__ import annotations

import hashlib
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from ipaddress import ip_address
from pathlib import Path
from typing import Annotated, Literal
from uuid import UUID

from fastapi import Depends, Request
from redis.exceptions import RedisError

from aegisnet.adapters.files.spool import Spool
from aegisnet.config import Settings
from aegisnet.domain.assets import IPAddress
from aegisnet.domain.auth import (
    NotAuthenticatedError,
    Permission,
    PermissionDeniedError,
    Principal,
)
from aegisnet.domain.enums import AuditResult
from aegisnet.domain.ports import RateLimiter
from aegisnet.logging import correlation_id_var, get_logger
from aegisnet.services.asset_service import AssetService
from aegisnet.services.audit_service import AuditReadService, AuditService
from aegisnet.services.auth_service import AuthService
from aegisnet.services.event_read_service import EventReadService
from aegisnet.services.ingest_service import IngestService

logger = get_logger(__name__)

INGEST_TOKEN_HEADER = "X-Ingest-Token"  # noqa: S105 - a header name, not a credential
REFRESH_COOKIE = "aegisnet_refresh"


class RateLimitedError(Exception):
    def __init__(self, retry_after: int) -> None:
        self.retry_after = max(1, retry_after)
        super().__init__("rate limited")


@dataclass(frozen=True, slots=True)
class AppServices:
    """Everything a route may need, built once per process by ``main.create_app``."""

    settings: Settings
    auth: AuthService
    audit: AuditService
    audit_read: AuditReadService
    ingest: IngestService
    assets: AssetService
    events: EventReadService
    limiter: RateLimiter
    spool: Spool
    enqueue_upload: Callable[[UUID, str, str], Awaitable[str]]
    """Queues ``import_upload(batch_id, spool_name, source_label)``; returns a message id."""
    enqueue_import: Callable[[UUID, str, str], Awaitable[str]]
    """Queues ``import_dataset(batch_id, dataset_id, source_label)``; returns a message id."""


def services(request: Request) -> AppServices:
    installed: AppServices = request.app.state.services
    return installed


def client_ip(request: Request) -> IPAddress | None:
    """The transport peer only. Proxy headers are not trusted in Milestone 1."""
    if request.client is None:
        return None
    try:
        return ip_address(request.client.host)
    except ValueError:
        return None


def correlation_id() -> UUID | None:
    value = correlation_id_var.get()
    try:
        return None if value is None else UUID(value)
    except ValueError:
        return None


async def optional_principal(
    request: Request, svc: Annotated[AppServices, Depends(services)]
) -> Principal | None:
    """Bearer access token or service token; ``None`` when neither header is present.
    A present-but-invalid credential is refused, never downgraded to anonymous."""
    principal: Principal | None = None
    authorization = request.headers.get("Authorization")
    service_token = request.headers.get(INGEST_TOKEN_HEADER)
    if authorization:
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not token.strip():
            raise NotAuthenticatedError("unsupported authorization scheme")
        principal = await svc.auth.authenticate_access(token.strip())
    elif service_token:
        principal = await svc.auth.authenticate_service_token(service_token.strip())
    # Exception handlers cannot see dependency results; the validation handler reads this
    # to attribute a refused import to its caller (api-milestone-1 acceptance: traversal
    # attempts are audited).
    request.state.principal = principal
    return principal


def require(permission: Permission) -> Callable[..., Awaitable[Principal]]:
    """Dependency factory: authenticate, then demand ``permission``; audit a denial."""

    async def dependency(
        request: Request,
        svc: Annotated[AppServices, Depends(services)],
        principal: Annotated[Principal | None, Depends(optional_principal)],
    ) -> Principal:
        if principal is None:
            raise NotAuthenticatedError("authentication required")
        if not principal.can(permission):
            await svc.audit.record(
                "rbac.denied",
                target_type="route",
                target_id=f"{request.method} {request.url.path}",
                result=AuditResult.denied,
                detail={"permission": permission.value, "role": principal.role},
                principal=principal,
                actor_ip=client_ip(request),
                correlation_id=correlation_id(),
            )
            raise PermissionDeniedError(permission)
        return principal

    dependency.aegisnet_permission = permission  # type: ignore[attr-defined]
    dependency.__name__ = f"require_{permission.name}"
    return dependency


async def enforce_limit(
    limiter: RateLimiter,
    name: str,
    subject: str,
    *,
    limit: int,
    window_seconds: int,
    cost: int = 1,
    fail_open: bool,
) -> None:
    try:
        decision = await limiter.hit(
            name, subject, limit=limit, window_seconds=window_seconds, cost=cost
        )
    except RedisError:
        logger.error("rate_limiter_unavailable", extra={"limit": name, "fail_open": fail_open})
        if fail_open:
            return
        raise RateLimitedError(retry_after=30) from None
    if not decision.allowed:
        raise RateLimitedError(decision.retry_after)


def rate_limit(kind: Literal["read", "default"]) -> Callable[..., Awaitable[None]]:
    """Per-principal limits for authenticated routes; login and ingest set their own."""

    async def dependency(
        svc: Annotated[AppServices, Depends(services)],
        principal: Annotated[Principal | None, Depends(optional_principal)],
        request: Request,
    ) -> None:
        subject = principal.subject if principal else f"ip:{client_ip(request)}"
        limit = (
            svc.settings.rate_limit_read_per_min
            if kind == "read"
            else svc.settings.rate_limit_default_per_min
        )
        await enforce_limit(
            svc.limiter, kind, subject, limit=limit, window_seconds=60, fail_open=True
        )

    dependency.__name__ = f"rate_limit_{kind}"
    return dependency


def hashed_subject(value: str) -> str:
    """A stable, non-reversible key for a rate-limit subject such as an e-mail address."""
    return hashlib.sha256(value.strip().lower().encode("utf-8")).hexdigest()[:24]


def spool_dir(settings: Settings) -> Path:
    return settings.spool_dir
