# syntax=docker/dockerfile:1.7
#
# Multi-stage backend image.
#   deps    — resolves the locked dependency set (no dev group)
#   dev     — deps + dev group, used by docker-compose.test.yml and CI
#   runtime — minimal non-root image used by the api and worker services
#
# Base images are pinned by minor version and stay that way: decision F-5, re-examined in
# Chunk 30 and kept, because nothing in this repository bumps a digest, so pinning without an
# updater would freeze the images and stop security patches arriving. The compensating control
# is the `images` job in .github/workflows/security.yml and the record is residual risk R-10.
# `make pin-digests` prints the digests for anyone who decides otherwise.

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

# What a scan is looking at: the `images` job builds and scans `aegisnet-api:latest`, and these
# say where it came from. Deliberately no `image.version` — the version already lives in three
# files and a fourth copy with nothing keeping it in step goes stale unnoticed — and no
# `image.revision`, which is a sharper story: it read `${GIT_SHA}`, and SonarCloud rated the
# result a security finding on new code. Four bisection rounds located it here (E-96). The
# label was a nicety; an analysis scope with a Dockerfile carved out of it is not, so the
# label went. `GIT_SHA` still reaches the running container as an environment variable.
LABEL org.opencontainers.image.title="aegisnet-api" \
      org.opencontainers.image.source="https://github.com/pchrysostomou/aegisnet" \
      org.opencontainers.image.licenses="MIT"

# procps supplies pgrep for the worker liveness healthcheck; curl is not installed on purpose.
RUN apt-get update \
 && apt-get install -y --no-install-recommends procps \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --create-home --uid 10001 --shell /usr/sbin/nologin aegisnet

COPY --from=deps /opt/venv /opt/venv
WORKDIR /app
COPY --chown=aegisnet:aegisnet src ./src
COPY --chown=aegisnet:aegisnet pyproject.toml alembic.ini ./
# The upload spool (SPOOL_DIR, ADR-016). Created here, owned by the runtime user, so the
# named volume Compose mounts over it inherits that ownership on first use instead of
# root's; the process must never need to be root to write an upload.
# Both mount points exist in the image on purpose. Docker will happily create a missing
# bind-mount destination, but that write lands on the container's own layer — which is
# exactly what `read_only: true` forbids (T-5.1). `/app/samples` is mounted read-only from
# the host and `/app/spool` is a named volume; neither needs a writable rootfs to work,
# and neither may depend on one.
RUN mkdir -p /app/spool /app/samples && chown aegisnet:aegisnet /app/spool /app/samples

USER aegisnet
EXPOSE 8000
CMD ["uvicorn", "aegisnet.main:app", "--host", "0.0.0.0", "--port", "8000"]
