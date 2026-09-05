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
- `api/errors.py` — one error envelope for every failure, with no internals disclosed; a
  rejected `dataset_id` on the import route is audited with the field name only (Chunk 7)
- `api/v1/health.py` — `/healthz` liveness and `/readyz` readiness, where readiness means
  PostgreSQL and Redis reachability and nothing else
- `api/v1/meta.py` — `/api/v1/meta/version` (requires `meta.read` since Chunk 6)
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
- `domain/detectors/` — the detector contract (bounded windows and results, sampled
  evidence, dedup keys), the recorded severity formula, the registry and the rules D-001
  port scan, D-002 auth-failure burst and D-003 DNS anomaly (ADR-017,
  `docs/detection-rules.md`); pure like the rest of `domain/`
- `services/ingest_service.py` — the ingest use-case: streaming, chunked, idempotent;
  batch and reject listing
- `services/asset_service.py`, `services/event_read_service.py` — the inventory and the
  bounded event reads; `adapters/db/asset_store.py`, `adapters/db/event_read_store.py`
  implement their ports (the latter also loads detection windows)
- `services/detection_service.py` — the sweep: registry sync, one load per interval sliced
  on each rule's grid, severity with the inventory's criticality, per-rule failure isolation
  (ADR-018); `adapters/db/detection_store.py` — rules, runs and alerts with the UNIQUE
  dedup key; `adapters/queue/detection_queue.py` — enqueue a sweep by actor name
- `workers/main.py`, `workers/actors.py` — the worker entrypoint (`dramatiq
  aegisnet.workers.main`) and the `import_dataset`, `import_upload` and `run_detectors` actors
- `domain/auth.py` — permissions, the role matrix, principals, the password policy and
  the hashed-token helpers; `services/auth_service.py` — Argon2id login with lockout,
  HS256 access tokens, rotating refresh tokens with reuse detection, logout denylist,
  service tokens; `services/audit_service.py` — the bounded audit writer and reader
  (ADR-016)
- `api/deps.py` — the deny-by-default `require(permission)` dependency, rate-limit
  dependencies, the `AppServices` container the routes read from; `api/schemas.py` — the
  request and response DTOs; `api/v1/auth.py`, `ingest.py`, `assets.py`, `events.py`,
  `audit.py` — the Milestone 1 routes
- `adapters/db/auth_store.py`, `adapters/db/audit_store.py` — the SQL user, refresh-token,
  service-token and audit stores; `adapters/cache/rate_limiter.py` — fixed-window limiter
  and access-token denylist on Redis; `adapters/files/spool.py`, `adapters/files/ndjson.py` — the capped upload spool and
  async NDJSON line reading
- `cli.py` — `python -m aegisnet.cli` with `datasets`, `import-dataset`, `batch`,
  `batches`, `rejects`, `seed-assets`, `assets`, `asset`, `resolve`, `events`,
  `event-stats`, `create-user`, `users`, `create-service-token`, `revoke-service-token`,
  `service-tokens`, `run-detectors`, `alerts`, `alert`, `detector-runs`

No detection exists yet; `SECURITY.md` at the repository root describes what the auth
layer enforces and what it still lacks.

## Tests

The default suite is hermetic: no PostgreSQL, no Redis, no network. The database suite is
opt-in and needs the ephemeral PostgreSQL from `docker-compose.test.yml --profile db`.

| Directory | Marker | What it covers |
|---|---|---|
| `tests/unit/` | `unit` | settings, log hygiene, broker factory, `bootstrap_env.py`; EVE sanitiser, limits, schema, hash and normaliser over `tests/fixtures/eve/`; the synthetic generator; the ingest, asset and event read services against in-memory stores; asset rules, cursors, the CLI and the seed loader; the auth domain and service (lockout, rotation, reuse, forged tokens), the audit writer's bounds, the Redis limiter and denylist on `fakeredis`, the spool, the auth CLI commands |
| `tests/detectors/` | `unit` | the detector contract's bounds, the severity formula and its reproduction, the thresholds, guards, samples and purity of D-001, D-002 and D-003, the registry, every labelled fixture under `tests/fixtures/labelled/` (pinned to `tools/gen_labelled_fixtures.py`), and the sweep service against fakes (registry sync, grid buckets, severity from the inventory, dedup on re-sweep, disabled and capped runs, a raising rule isolated) |
| `tests/integration/` | `integration` | the assembled app in-process over `tests/fakes.py` (in-memory stores, a settable clock, a breakable limiter): health, readiness with faked probes, version, correlation IDs; the auth, ingest, asset, event and audit routes including cookies, refresh replay, rate limits and the audit trail each route leaves; the committed corpus, its manifest and the registry checksum |
| `tests/security/` | `security` | THREAT_MODEL mitigations: the error envelope (T-2.7), and the committed Compose files, Dockerfiles, `.env.example`, `.gitignore` and pre-commit config read as data (T-5.1, T-5.2, T-5.4); payload limits (T-1.4, T-1.5); dataset path traversal (T-1.6); pagination bounds (T-2.6); the RBAC route enumeration and role × route matrix, credential downgrade refusal and audited denials (T-2.1, T-2.2, T-2.4) |
| `tests/db/` | `db` (+ `integration` / `security`) | the baseline revision against a real PostgreSQL 16: the nine tables and enum types, ORM/schema agreement via `compare_metadata`, constraint behaviour, the runtime role's privilege matrix and the audit-log guarantee (T-2.5, T-5.3), downgrade to base; the SQL ingest store (idempotent corpus import, provenance, rejects, promoted columns), the `import_dataset` actor through a `StubBroker`, the asset store (resolution precedence, atomic bulk, seeding) and the event read store (filters, a full keyset walk, stats, batch and reject listing); the SQL user, refresh-token, service-token and audit stores, and the auth service end to end on PostgreSQL |

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
