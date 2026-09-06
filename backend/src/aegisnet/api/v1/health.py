"""Liveness and readiness endpoints.

``/healthz`` answers "is this process running".

``/readyz`` answers "can this process reach the two dependencies it cannot serve a request
without", which means PostgreSQL and Redis connectivity and nothing else. It deliberately
makes **no** claim about ingestion, normalisation, queue depth, or worker capability: those
all exist, and none of them is a reason to take the API out of a load balancer.

Per-component detail is withheld from the response so that an unauthenticated caller
cannot map internal dependencies (decision F-15). Detail is available in the server log
under the request's correlation id; no authenticated per-component view was ever built.
"""

from __future__ import annotations

import asyncio
from typing import Literal

from fastapi import APIRouter, Request, Response, status
from pydantic import BaseModel

from aegisnet.logging import get_logger

logger = get_logger(__name__)
router = APIRouter(tags=["health"])


class HealthResponse(BaseModel):
    status: Literal["ok"]


class ReadinessResponse(BaseModel):
    status: Literal["ok", "degraded"]


@router.get("/healthz", response_model=HealthResponse, summary="Liveness probe")
async def healthz() -> HealthResponse:
    return HealthResponse(status="ok")


@router.get(
    "/readyz",
    response_model=ReadinessResponse,
    summary="Readiness probe (PostgreSQL and Redis only)",
    responses={status.HTTP_503_SERVICE_UNAVAILABLE: {"model": ReadinessResponse}},
)
async def readyz(request: Request, response: Response) -> ReadinessResponse:
    probes = request.app.state.readiness_probes
    timeout = request.app.state.settings.probe_timeout_seconds

    async def run(name: str) -> tuple[str, bool]:
        try:
            async with asyncio.timeout(timeout):
                return name, bool(await probes[name]())
        except Exception as exc:  # noqa: BLE001 - a failed probe is a normal outcome here
            logger.warning(
                "readiness_probe_failed",
                extra={"component": name, "exception_type": type(exc).__name__},
            )
            return name, False

    results = dict(await asyncio.gather(*(run(name) for name in probes)))
    if all(results.values()):
        return ReadinessResponse(status="ok")

    logger.warning(
        "readiness_degraded", extra={"failing": sorted(k for k, ok in results.items() if not ok)}
    )
    response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return ReadinessResponse(status="degraded")
