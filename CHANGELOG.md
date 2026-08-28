# Changelog

All notable changes to AegisNet are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Nothing is released yet. There is no tagged version.

## [Unreleased]

### Added
- Repository scaffolding: ignore rules that treat secrets, packet captures, and live sensor
  output as never-committable; Docker ignore rules; MIT licence; this changelog.
- `.env.example` environment template using `__REPLACE_ME__` placeholders, and
  `infra/scripts/bootstrap_env.py` (`make bootstrap`) which generates a local
  development-only `.env` with cryptographically random secrets, idempotently and without
  printing any value (ADR-011).
- Pre-commit configuration: whitespace and merge-conflict hooks, Ruff, gitleaks, and a hook
  that hard-fails if `.env` is ever staged.
- Milestone 0 planning package: PRD, architecture, threat model, repository structure, data
  model, Milestone 1 API contract, six-milestone delivery plan, evaluation plan, and status
  record.
- ADR-009 (defer the isolated Suricata lab to Milestone 2), ADR-010 (defer the scheduler and
  periodiq to Milestone 2), ADR-011 (bootstrap-generated development secrets).
- Docker Compose topology for five services (`db`, `redis`, `api`, `worker`, `web`): every
  published port bound to `127.0.0.1`, no host port at all on `db`, `redis` or `worker`,
  `cap_drop: ["ALL"]` and `no-new-privileges:true` everywhere, dependency ordering via
  healthchecks. The worker probe is process liveness only and makes no readiness claim.
- Multi-stage backend and frontend images, both ending on a non-root `USER`, with matching
  `.dockerignore` files; a hermetic test/lint runner in `docker-compose.test.yml`; an example
  local override file, with `docker-compose.override.yml` itself gitignored.
- PostgreSQL initialisation creating two least-privilege roles, `aegisnet_migrator` and
  `aegisnet_app`. It validates every interpolated role name and secret against a strict
  allowlist and fails closed, and it creates no tables.
- `make compose-config`, `compose-ps`, `compose-logs`, `compose-down`, `pin-digests`, and a
  `require-env` guard. `up` and `build` are intentionally absent until the services they
  start have source and lockfiles.
- hadolint configuration waiving only DL3006 and DL3008, each with a recorded reason.
- Backend FastAPI application: settings whose secrets are `SecretStr` and which refuse to
  load while any value is still a `.env.example` placeholder outside `ENV=test`; JSON
  logging with correlation-ID propagation, literal-secret scrubbing and control-character
  neutralisation of untrusted values; a single error envelope that discloses no traceback,
  SQL or path; `GET /healthz`; `GET /readyz`; `GET /api/v1/meta/version`.
- Async PostgreSQL engine and async Redis client, connectivity only. A Dramatiq broker that
  registers **zero** actors (ADR-010) so the worker's topology is proven without inventing a
  workload.
- `backend/uv.lock`, committed so `uv sync --frozen` and the image build are reproducible.
  `backend/Dockerfile` already requires it.
- `make backend-install`, `lint`, `format`, `format-check`, `typecheck`, and an aggregate
  `check`. `test` remains absent until a suite exists.

### Changed
- Ruff now also enforces `BLE` (blind `except`). The one intentional broad catch, a failed
  readiness probe, carries an explicit waiver.

### Fixed
- `.env.example` no longer places comments on the same line as an assignment. Docker Compose
  `env_file` does not strip a trailing `# comment`, so `SECRET_KEY` would have been delivered
  to the container with the comment text appended to its value.
- The log sanitiser now strips LF and CR. It previously allowed both, so a newline inside an
  untrusted value survived; the JSON encoder escaped it, but any future non-JSON log sink
  would have made log-line forgery possible.
- `backend/pyproject.toml` declared `readme = "../README.md"`. A readme outside the project
  directory is rejected by the build backend, which made the package impossible to build or
  install; `backend/README.md` now holds the package-level readme.
- `docker-compose.test.yml` inlined four literal credential values. It now sets no secret
  variables at all and relies on the placeholder defaults, which only `ENV=test` accepts. The
  existing "no inline secret literals" security test covered `docker-compose.yml` but not the
  test runner, so this went unnoticed; that gap is closed when the suite lands.

### Not yet present
Frontend placeholder, tests, CI and security workflows, database migrations, ORM models,
Suricata EVE schemas and normalisation, ingestion endpoints, dataset registry, background
actors, asset and event APIs, authentication, RBAC, audit logging, rate limiting, detectors,
correlation, Perplexity integration, reports, dashboard.
