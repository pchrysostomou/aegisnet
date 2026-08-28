# AegisNet backend

FastAPI application for the AegisNet defensive network threat detection lab. Project
documentation lives at the repository root: [`../README.md`](../README.md),
[`../ARCHITECTURE.md`](../ARCHITECTURE.md), [`../THREAT_MODEL.md`](../THREAT_MODEL.md), and
[`../docs/`](../docs).

This file exists because Python packaging requires the `readme` path to sit inside the
project directory; pointing it at the repository root makes the package unbuildable.

## What this package contains

Application foundation only:

- `config.py` — settings with `SecretStr` secrets that refuse to load while any value is
  still a `.env.example` placeholder outside the test environment
- `logging.py` — JSON logging, correlation IDs, secret scrubbing, control-character
  neutralisation for untrusted content
- `api/errors.py` — one error envelope for every failure, with no internals disclosed
- `api/v1/health.py` — `/healthz` liveness and `/readyz` readiness, where readiness means
  PostgreSQL and Redis reachability and nothing else
- `api/v1/meta.py` — `/api/v1/meta/version`
- `adapters/` — async PostgreSQL engine, async Redis client, Dramatiq broker

No ORM models, migrations, ingestion, detection, authentication, or background actors exist
yet. The Dramatiq broker registers **zero** actors.

## Local commands

```bash
uv sync              # install the locked dependency set
uv run ruff check .  # lint
uv run mypy          # typecheck
```

Run these from this directory. Repository-level targets are in [`../Makefile`](../Makefile).
