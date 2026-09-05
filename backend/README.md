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
- `adapters/db/engine.py`, `adapters/cache` — async PostgreSQL engine and async Redis
  client, connectivity only
- `adapters/db/models.py` — SQLAlchemy 2.0 models for the nine Milestone 1 tables
- `adapters/db/migrations/` — the Alembic environment and revisions, shipped inside the
  package so the runtime image can run `alembic upgrade head` (ADR-012); `alembic.ini`
  at this directory's root points here and carries no URL
- `domain/enums.py` — the schema enumerations, on the pure side so the ORM and the EVE
  normaliser can share them
- `domain/models.py` — frozen value objects: `NormalizedEvent`, `Reject`
- `domain/eve/` — parse limits, sanitiser, EVE schema, canonical `event_hash`, normaliser;
  pure and clock-free (ADR-013)
- `adapters/files/registry.py` — `samples/registry.yml` loader and id-only, symlink-free,
  checksum-verified dataset resolution (T-1.6)
- `adapters/db/session.py`, `adapters/db/ingest_store.py` — session factory and the SQL
  implementation of the `IngestStore` port, running as the runtime role
- `adapters/queue/broker.py` — Dramatiq broker factory with an explicitly authenticated
  Redis client and no import-time side effects; `names.py` (queue and actor names) and
  `ingest_queue.py` (enqueue by name, ids only)
- `domain/ports.py` — the `IngestStore`, `AssetStore` and `EventReadStore` Protocols and
  their value objects (ADR-014, ADR-015); `domain/pagination.py` — bounded keyset cursors
- `domain/assets.py` — asset specs, overlap detection and the reference CIDR resolver
- `services/ingest_service.py` — the ingest use-case: streaming, chunked, idempotent;
  batch and reject listing
- `services/asset_service.py`, `services/event_read_service.py` — the inventory and the
  bounded event reads; `adapters/db/asset_store.py`, `adapters/db/event_read_store.py`
  implement their ports
- `workers/main.py`, `workers/actors.py` — the worker entrypoint (`dramatiq
  aegisnet.workers.main`) and the `import_dataset` actor
- `cli.py` — `python -m aegisnet.cli datasets | import-dataset | batch`

No HTTP ingest route, detection, or authentication exists yet.

## Tests

The default suite is hermetic: no PostgreSQL, no Redis, no network. The database suite is
opt-in and needs the ephemeral PostgreSQL from `docker-compose.test.yml --profile db`.

| Directory | Marker | What it covers |
|---|---|---|
| `tests/unit/` | `unit` | settings, log hygiene, broker factory, `bootstrap_env.py`; EVE sanitiser, limits, schema, hash and normaliser over `tests/fixtures/eve/`; the synthetic generator; the ingest, asset and event read services against in-memory stores; asset rules, cursors, the CLI and the seed loader |
| `tests/integration/` | `integration` | the assembled app in-process: health, readiness with faked probes, version, correlation IDs; the committed corpus, its manifest and the registry checksum |
| `tests/security/` | `security` | THREAT_MODEL mitigations: the error envelope (T-2.7), and the committed Compose files, Dockerfiles, `.env.example`, `.gitignore` and pre-commit config read as data (T-5.1, T-5.2, T-5.4); payload limits (T-1.4, T-1.5); dataset path traversal (T-1.6); pagination bounds (T-2.6) |
| `tests/db/` | `db` (+ `integration` / `security`) | the baseline revision against a real PostgreSQL 16: the nine tables and enum types, ORM/schema agreement via `compare_metadata`, constraint behaviour, the runtime role's privilege matrix and the audit-log guarantee (T-2.5, T-5.3), downgrade to base; the SQL ingest store (idempotent corpus import, provenance, rejects, promoted columns), the `import_dataset` actor through a `StubBroker`, the asset store (resolution precedence, atomic bulk, seeding) and the event read store (filters, a full keyset walk, stats, batch and reject listing) |

`conftest.py` sets `ENV=test` before the package is imported so that collection does not
depend on the developer's shell.

## Local commands

```bash
uv sync --frozen                 # install the locked dependency set
uv run ruff check src tests      # lint
uv run ruff format --check src tests
uv run mypy                      # typecheck (strict on domain/)
uv run lint-imports              # domain purity and layering contracts
SAMPLES_DIR=../samples uv run python -m aegisnet.cli datasets   # needs no database
ENV=test uv run pytest           # the hermetic suite (database tests are skipped)
ENV=test uv run pytest --cov=aegisnet --cov-report=term-missing
uv run alembic heads             # the revision this build expects
```

Run these from this directory. Repository-level targets are in [`../Makefile`](../Makefile);
`make migrate` applies the revisions inside the api image, and `make test-db` runs the
database suite.
