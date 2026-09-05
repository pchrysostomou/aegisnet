# syntax=docker/dockerfile:1.7
#
# Multi-stage backend image.
#   deps    — resolves the locked dependency set (no dev group)
#   dev     — deps + dev group, used by docker-compose.test.yml and CI
#   runtime — minimal non-root image used by the api and worker services
#
# Base images are pinned by minor version. Digest pinning is decision F-5 and is NOT
# applied yet; run `make pin-digests`.

ARG UV_IMAGE=ghcr.io/astral-sh/uv:python3.12-bookworm-slim
ARG PY_IMAGE=python:3.12-slim-bookworm

# ---------------------------------------------------------------- deps
FROM ${UV_IMAGE} AS deps
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/venv
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-install-project

# ---------------------------------------------------------------- dev
FROM deps AS dev
ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONPATH=/app/src \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
WORKDIR /app
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-install-project
COPY . .
# Tests run as a non-root user too.
RUN useradd --create-home --uid 10001 aegisnet && chown -R aegisnet:aegisnet /app /opt/venv
USER aegisnet

# ---------------------------------------------------------------- runtime
FROM ${PY_IMAGE} AS runtime
ARG GIT_SHA=unknown
ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONPATH=/app/src \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    GIT_SHA=${GIT_SHA}

# procps supplies pgrep for the worker liveness healthcheck; curl is not installed on purpose.
RUN apt-get update \
 && apt-get install -y --no-install-recommends procps \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --create-home --uid 10001 --shell /usr/sbin/nologin aegisnet

COPY --from=deps /opt/venv /opt/venv
WORKDIR /app
COPY --chown=aegisnet:aegisnet src ./src
COPY --chown=aegisnet:aegisnet pyproject.toml alembic.ini ./

USER aegisnet
EXPOSE 8000
CMD ["uvicorn", "aegisnet.main:app", "--host", "0.0.0.0", "--port", "8000"]
