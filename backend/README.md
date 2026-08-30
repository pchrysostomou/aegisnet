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
- `adapters/db`, `adapters/cache` — async PostgreSQL engine and async Redis client,
  connectivity only
- `adapters/queue/broker.py` — Dramatiq broker factory with an explicitly authenticated
  Redis client and no import-time side effects
- `adapters/queue/worker.py` — the worker process entrypoint (`dramatiq
  aegisnet.adapters.queue.worker`); registers **zero** actors (ADR-010)

No ORM models, migrations, ingestion, detection, authentication, or background actors exist
yet.

## Tests

`tests/` is hermetic: no PostgreSQL, no Redis, no network.

| Directory | Marker | What it covers |
|---|---|---|
| `tests/unit/` | `unit` | settings, log hygiene, broker factory, `bootstrap_env.py` |
| `tests/integration/` | `integration` | the assembled app in-process: health, readiness with faked probes, version, correlation IDs |
| `tests/security/` | `security` | THREAT_MODEL mitigations: the error envelope (T-2.7), and the committed Compose files, Dockerfiles, `.env.example`, `.gitignore` and pre-commit config read as data (T-5.1, T-5.2, T-5.4) |

`conftest.py` sets `ENV=test` before the package is imported so that collection does not
depend on the developer's shell.

## Local commands

```bash
uv sync --frozen                 # install the locked dependency set
uv run ruff check src tests      # lint
uv run ruff format --check src tests
uv run mypy                      # typecheck
ENV=test uv run pytest           # the suite
ENV=test uv run pytest --cov=aegisnet --cov-report=term-missing
```

Run these from this directory. Repository-level targets are in [`../Makefile`](../Makefile).
