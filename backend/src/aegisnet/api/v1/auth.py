"""Login, refresh, logout, me (FR-10.1, T-2.1, T-2.4).

``/login`` and ``/refresh`` are the two routes without a permission dependency: one
creates the session, the other renews it from the HttpOnly refresh cookie. Both are rate
limited by client address, login also per account, and every outcome is audited.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response, status
from fastapi.responses import JSONResponse

from aegisnet.api.deps import (
    REFRESH_COOKIE,
    AppServices,
    client_ip,
    correlation_id,
    enforce_limit,
    hashed_subject,
    rate_limit,
    require,
    services,
)
from aegisnet.api.errors import invalid_credentials_response
from aegisnet.api.schemas import LoginRequest, TokenResponse, UserOut
from aegisnet.domain.auth import InvalidCredentialsError, Permission, Principal, RefreshReuseError
from aegisnet.domain.enums import AuditResult
from aegisnet.services.auth_service import LoginOutcome, LoginRejectedError

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])

LOGIN_WINDOW_SECONDS = 15 * 60


def _set_refresh_cookie(response: Response, outcome: LoginOutcome, svc: AppServices) -> None:
    response.set_cookie(
        REFRESH_COOKIE,
        outcome.refresh_token,
        max_age=svc.settings.refresh_ttl_days * 24 * 3600,
        expires=outcome.refresh_expires_at,
        path="/api/v1/auth",
        secure=svc.settings.cookie_secure,
        httponly=True,
        samesite="strict",
    )


def _clear_refresh_cookie(response: Response, svc: AppServices) -> None:
    response.delete_cookie(
        REFRESH_COOKIE,
        path="/api/v1/auth",
        secure=svc.settings.cookie_secure,
        httponly=True,
        samesite="strict",
    )


@router.post("/login", response_model=TokenResponse, summary="Password login")
async def login(
    body: LoginRequest,
    request: Request,
    response: Response,
    svc: Annotated[AppServices, Depends(services)],
) -> TokenResponse:
    ip = client_ip(request)
    ip_key = "unknown" if ip is None else str(ip)
    await enforce_limit(
        svc.limiter,
        "login_ip",
        ip_key,
        limit=svc.settings.rate_limit_login_ip_per_15min,
        window_seconds=LOGIN_WINDOW_SECONDS,
        fail_open=False,
    )
    await enforce_limit(
        svc.limiter,
        "login_account",
        hashed_subject(body.email),
        limit=svc.settings.rate_limit_login_per_15min,
        window_seconds=LOGIN_WINDOW_SECONDS,
        fail_open=False,
    )
    try:
        outcome = await svc.auth.login(
            body.email,
            body.password,
            ip=ip_key,
            user_agent=request.headers.get("user-agent"),
        )
    except LoginRejectedError as error:
        await svc.audit.record(
            "auth.login_failed",
            target_type="user",
            target_id=None if error.failure.user_id is None else str(error.failure.user_id),
            result=AuditResult.denied,
            detail={"reason": error.failure.reason, "locked": error.failure.locked},
            actor_ip=ip,
            correlation_id=correlation_id(),
        )
        raise
    await svc.audit.record(
        "auth.login_success",
        target_type="user",
        target_id=str(outcome.user.id),
        actor_user_id=outcome.user.id,
        actor_ip=ip,
        correlation_id=correlation_id(),
    )
    _set_refresh_cookie(response, outcome, svc)
    return TokenResponse(access_token=outcome.access_token, expires_in=outcome.access_expires_in)


@router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Rotate the refresh cookie and mint a new access token",
    dependencies=[Depends(rate_limit("default"))],
)
async def refresh(
    request: Request, response: Response, svc: Annotated[AppServices, Depends(services)]
) -> Response:
    """A refused refresh answers 401 *and* clears the cookie: a dead token is never resent."""
    ip = client_ip(request)
    presented = request.cookies.get(REFRESH_COOKIE)
    if not presented:
        return _refused(svc)
    try:
        outcome = await svc.auth.refresh(
            presented,
            ip=None if ip is None else str(ip),
            user_agent=request.headers.get("user-agent"),
        )
    except RefreshReuseError:
        await svc.audit.record(
            "auth.refresh_reuse_detected",
            target_type="refresh_token",
            result=AuditResult.denied,
            actor_ip=ip,
            correlation_id=correlation_id(),
        )
        return _refused(svc)
    except InvalidCredentialsError:
        return _refused(svc)
    await svc.audit.record(
        "auth.refresh",
        target_type="user",
        target_id=str(outcome.user.id),
        actor_user_id=outcome.user.id,
        actor_ip=ip,
        correlation_id=correlation_id(),
    )
    _set_refresh_cookie(response, outcome, svc)
    body = TokenResponse(access_token=outcome.access_token, expires_in=outcome.access_expires_in)
    return JSONResponse(body.model_dump(mode="json"), headers=response.headers)


def _refused(svc: AppServices) -> JSONResponse:
    refused = invalid_credentials_response()
    _clear_refresh_cookie(refused, svc)
    return refused


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke the refresh chain and the current access token",
)
async def logout(
    request: Request,
    response: Response,
    svc: Annotated[AppServices, Depends(services)],
    principal: Annotated[Principal, Depends(require(Permission.auth_self))],
) -> Response:
    revoked = await svc.auth.logout(request.cookies.get(REFRESH_COOKIE), principal)
    await svc.audit.record(
        "auth.logout",
        target_type="user",
        target_id=str(principal.id),
        detail={"sessions_revoked": revoked},
        principal=principal,
        actor_ip=client_ip(request),
        correlation_id=correlation_id(),
    )
    out = Response(status_code=status.HTTP_204_NO_CONTENT)
    _clear_refresh_cookie(out, svc)
    return out


@router.get("/me", response_model=UserOut, summary="The calling user")
async def me(
    svc: Annotated[AppServices, Depends(services)],
    principal: Annotated[Principal, Depends(require(Permission.auth_self))],
) -> UserOut:
    user = await svc.auth.current_user(principal)
    return UserOut.from_record(user)
