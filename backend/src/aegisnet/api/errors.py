"""Global error handling.

Every failure leaves the API in the documented envelope shape:

    {"error": {"code": ..., "message": ..., "correlation_id": ..., "details": [...]}}

No traceback, SQL fragment, filesystem path, or internal identifier is ever included
(THREAT_MODEL T-2.7). The correlation ID lets an operator find the full server-side
record without exposing anything to the caller.
"""

from __future__ import annotations

from typing import Any, Final

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from aegisnet.adapters.files.registry import (
    ChecksumMismatchError,
    DatasetNotFoundError,
    InvalidRegistryError,
    UnsafeDatasetPathError,
)
from aegisnet.adapters.files.spool import SpoolTooLargeError
from aegisnet.api.deps import RateLimitedError, client_ip, correlation_id
from aegisnet.domain.assets import (
    AssetNotFoundError,
    BulkTooLargeError,
    HostnameConflictError,
    NetworkOverlapError,
)
from aegisnet.domain.auth import (
    InvalidCredentialsError,
    NotAuthenticatedError,
    PasswordPolicyError,
    PermissionDeniedError,
    RefreshReuseError,
)
from aegisnet.domain.enums import AuditResult
from aegisnet.domain.pagination import InvalidCursorError
from aegisnet.logging import correlation_id_var, get_logger
from aegisnet.services.detection_service import AlertNotFoundError, SweepError
from aegisnet.services.event_read_service import EventNotFoundError, EventQueryError
from aegisnet.services.ingest_service import BatchNotFoundError, IngestLimitExceededError

logger = get_logger(__name__)

GENERIC_SERVER_MESSAGE = "An internal error occurred. Quote the correlation id when reporting it."


class PayloadTooLargeError(Exception):
    """A body, line count or batch exceeds a documented cap (T-1.4)."""


class ValidationFailedError(Exception):
    """A route-level check a Pydantic model could not express."""

    def __init__(self, field: str, issue: str) -> None:
        self.field = field
        self.issue = issue
        super().__init__(issue)


def _envelope(
    code: str, message: str, details: list[dict[str, Any]] | None = None
) -> dict[str, Any]:
    return {
        "error": {
            "code": code,
            "message": message,
            "correlation_id": correlation_id_var.get(),
            "details": details or [],
        }
    }


async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    code = {
        status.HTTP_401_UNAUTHORIZED: "unauthenticated",
        status.HTTP_403_FORBIDDEN: "forbidden",
        status.HTTP_404_NOT_FOUND: "not_found",
        status.HTTP_409_CONFLICT: "conflict",
        status.HTTP_413_CONTENT_TOO_LARGE: "payload_too_large",
        status.HTTP_429_TOO_MANY_REQUESTS: "rate_limited",
        status.HTTP_503_SERVICE_UNAVAILABLE: "service_unavailable",
    }.get(exc.status_code, "http_error")
    return JSONResponse(
        status_code=exc.status_code,
        content=_envelope(code, str(exc.detail)),
        headers=getattr(exc, "headers", None),
    )


AUDITED_FIELDS: Final = {"/api/v1/ingest/import": ("dataset_id",)}
"""Route → body fields whose rejection is worth an audit entry: a dataset id that fails its
grammar is the shape a path-traversal attempt takes (T-1.6)."""


async def _audit_rejected_fields(request: Request, fields: list[str]) -> None:
    matched = request.scope.get("route")
    watched = AUDITED_FIELDS.get(getattr(matched, "path", ""), ())
    hits = sorted({f.split(".")[-1] for f in fields if f.split(".")[-1] in watched})
    if not hits:
        return
    services = getattr(request.app.state, "services", None)
    if services is None:
        return
    await services.audit.record(
        "ingest.refused",
        target_type="ingest",
        result=AuditResult.denied,
        detail={"reason": "invalid_field", "fields": hits},  # the values are never recorded
        principal=getattr(request.state, "principal", None),
        actor_ip=client_ip(request),
        correlation_id=correlation_id(),
    )


async def validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    details = [
        {
            "field": ".".join(str(part) for part in error.get("loc", ())),
            "issue": error.get("msg", "invalid"),
        }
        for error in exc.errors()
    ]
    await _audit_rejected_fields(request, [str(d["field"]) for d in details])
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        content=_envelope("validation_failed", "Request failed validation.", details),
    )


KNOWN_METHODS: Final = {
    method: method for method in ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")
}


async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    # The exception type is logged; the response says nothing about it. Nothing the client
    # sent is logged either: the route is the matched template from the routing table (or
    # "unmatched"), and the method is looked up in a fixed set, so the log line carries
    # only server-owned strings (T-2.7, log injection).
    matched = request.scope.get("route")
    logger.error(
        "unhandled_exception",
        extra={
            "route": getattr(matched, "path", None) or "unmatched",
            "method": KNOWN_METHODS.get(request.method, "other"),
            "exception_type": type(exc).__name__,
        },
        exc_info=exc,
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=_envelope("internal_error", GENERIC_SERVER_MESSAGE),
    )


def _respond(
    status_code: int,
    code: str,
    message: str,
    *,
    details: list[dict[str, Any]] | None = None,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    return JSONResponse(
        status_code=status_code, content=_envelope(code, message, details), headers=headers
    )


def invalid_credentials_response() -> JSONResponse:
    """The refresh route builds this itself so it can also clear the dead cookie."""
    return _respond(status.HTTP_401_UNAUTHORIZED, "invalid_credentials", "Invalid credentials.")


async def not_authenticated_handler(request: Request, exc: NotAuthenticatedError) -> JSONResponse:
    return _respond(
        status.HTTP_401_UNAUTHORIZED,
        "unauthenticated",
        "Authentication required.",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def invalid_credentials_handler(
    request: Request, exc: InvalidCredentialsError
) -> JSONResponse:
    # Same body for a wrong password, an unknown account, a locked account, an expired or
    # reused refresh token: nothing here tells an attacker which one it was (T-2.1).
    return invalid_credentials_response()


async def forbidden_handler(request: Request, exc: PermissionDeniedError) -> JSONResponse:
    return _respond(status.HTTP_403_FORBIDDEN, "forbidden", "This action is not permitted.")


async def rate_limited_handler(request: Request, exc: RateLimitedError) -> JSONResponse:
    return _respond(
        status.HTTP_429_TOO_MANY_REQUESTS,
        "rate_limited",
        "Too many requests. Retry after the indicated number of seconds.",
        headers={"Retry-After": str(exc.retry_after)},
    )


async def not_found_handler(request: Request, exc: Exception) -> JSONResponse:
    return _respond(status.HTTP_404_NOT_FOUND, "not_found", "No such resource.")


async def conflict_handler(request: Request, exc: Exception) -> JSONResponse:
    code = "network_overlap" if isinstance(exc, NetworkOverlapError) else "conflict"
    return _respond(status.HTTP_409_CONFLICT, code, str(exc))


async def dataset_unavailable_handler(request: Request, exc: Exception) -> JSONResponse:
    return _respond(status.HTTP_409_CONFLICT, "dataset_unavailable", str(exc))


async def payload_too_large_handler(request: Request, exc: Exception) -> JSONResponse:
    return _respond(status.HTTP_413_CONTENT_TOO_LARGE, "payload_too_large", str(exc))


async def domain_validation_handler(request: Request, exc: Exception) -> JSONResponse:
    field = getattr(exc, "field", "query")
    issue = getattr(exc, "issue", str(exc))
    return _respond(
        status.HTTP_422_UNPROCESSABLE_CONTENT,
        "validation_failed",
        "Request failed validation.",
        details=[{"field": field, "issue": issue}],
    )


def register_error_handlers(app: FastAPI) -> None:
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)  # type: ignore[arg-type]
    app.add_exception_handler(RequestValidationError, validation_exception_handler)  # type: ignore[arg-type]
    app.add_exception_handler(NotAuthenticatedError, not_authenticated_handler)  # type: ignore[arg-type]
    app.add_exception_handler(InvalidCredentialsError, invalid_credentials_handler)  # type: ignore[arg-type]
    app.add_exception_handler(RefreshReuseError, invalid_credentials_handler)  # type: ignore[arg-type]
    app.add_exception_handler(PermissionDeniedError, forbidden_handler)  # type: ignore[arg-type]
    app.add_exception_handler(RateLimitedError, rate_limited_handler)  # type: ignore[arg-type]
    for missing in (
        AssetNotFoundError,
        BatchNotFoundError,
        EventNotFoundError,
        AlertNotFoundError,
        DatasetNotFoundError,
    ):
        app.add_exception_handler(missing, not_found_handler)
    for conflict in (HostnameConflictError, NetworkOverlapError):
        app.add_exception_handler(conflict, conflict_handler)
    for unavailable in (UnsafeDatasetPathError, ChecksumMismatchError, InvalidRegistryError):
        app.add_exception_handler(unavailable, dataset_unavailable_handler)
    for too_large in (
        PayloadTooLargeError,
        SpoolTooLargeError,
        IngestLimitExceededError,
        BulkTooLargeError,
    ):
        app.add_exception_handler(too_large, payload_too_large_handler)
    for invalid in (
        ValidationFailedError,
        EventQueryError,
        SweepError,
        InvalidCursorError,
        PasswordPolicyError,
    ):
        app.add_exception_handler(invalid, domain_validation_handler)
    app.add_exception_handler(Exception, unhandled_exception_handler)
