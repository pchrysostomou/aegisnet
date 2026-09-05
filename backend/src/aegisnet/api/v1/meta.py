"""Build metadata.

The git SHA is withheld in production to avoid disclosing the exact deployed commit to
an unauthenticated caller. This route becomes permission-gated in Chunk 6, when the
authentication layer exists; it is unauthenticated in Chunk 1 because no auth exists yet,
and that limitation is recorded in docs/STATUS.md rather than hidden.
"""

from __future__ import annotations

from fastapi import APIRouter, Request
from pydantic import BaseModel

from aegisnet.version import APP_VERSION, git_sha, schema_revision

router = APIRouter(prefix="/api/v1/meta", tags=["meta"])


class VersionResponse(BaseModel):
    app_name: str
    version: str
    environment: str
    git_sha: str | None = None
    schema_revision: str | None = None


@router.get("/version", response_model=VersionResponse, summary="Application version")
async def version(request: Request) -> VersionResponse:
    settings = request.app.state.settings
    return VersionResponse(
        app_name=settings.app_name,
        version=APP_VERSION,
        environment=str(settings.env),
        git_sha=None if settings.is_production else git_sha(),
        schema_revision=schema_revision(),
    )
