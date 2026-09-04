"""Global error handling.

Every failure leaves the API in the documented envelope shape:

    {"error": {"code": ..., "message": ..., "correlation_id": ..., "details": [...]}}

No traceback, SQL fragment, filesystem path, or internal identifier is ever included
(THREAT_MODEL T-2.7). The correlation ID lets an operator find the full server-side
record without exposing anything to the caller.
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from aegisnet.logging import correlation_id_var, get_logger, untrusted_text

logger = get_logger(__name__)

GENERIC_SERVER_MESSAGE = "An internal error occurred. Quote the correlation id when reporting it."


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
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        content=_envelope("validation_failed", "Request failed validation.", details),
    )


async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    # The exception type is logged; the response says nothing about it. Path and method
    # are request-derived, so they are neutralised here, at the log call, and not only by
    # the formatter.
    logger.error(
        "unhandled_exception",
        extra={
            "path": untrusted_text(request.url.path),
            "method": untrusted_text(request.method, max_chars=16),
            "exception_type": type(exc).__name__,
        },
        exc_info=exc,
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=_envelope("internal_error", GENERIC_SERVER_MESSAGE),
    )


def register_error_handlers(app: FastAPI) -> None:
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)  # type: ignore[arg-type]
    app.add_exception_handler(RequestValidationError, validation_exception_handler)  # type: ignore[arg-type]
    app.add_exception_handler(Exception, unhandled_exception_handler)
