"""Build metadata.

The git SHA is withheld in production to avoid disclosing the exact deployed commit. The
route requires ``meta.read``, which every role and service token holds (Chunk 6).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel

from aegisnet.api.deps import rate_limit, require
from aegisnet.domain.auth import Permission
from aegisnet.version import APP_VERSION, git_sha, schema_revision

router = APIRouter(prefix="/api/v1/meta", tags=["meta"])


class VersionResponse(BaseModel):
    app_name: str
    version: str
    environment: str
    git_sha: str | None = None
    schema_revision: str | None = None


@router.get(
    "/version",
    response_model=VersionResponse,
    summary="Application version (any authenticated principal)",
    dependencies=[Depends(require(Permission.meta_read)), Depends(rate_limit("read"))],
)
async def version(request: Request) -> VersionResponse:
    settings = request.app.state.settings
    return VersionResponse(
        app_name=settings.app_name,
        version=APP_VERSION,
        environment=str(settings.env),
        git_sha=None if settings.is_production else git_sha(),
        schema_revision=schema_revision(),
    )
