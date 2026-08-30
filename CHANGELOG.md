# Changelog

All notable changes to AegisNet are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Nothing is released yet. There is no tagged version.

## [Unreleased]

### Added
- Repository scaffolding: ignore rules that treat secrets, packet captures, and live sensor
  output as never-committable; Docker ignore rules; MIT licence; this changelog.
- `.gitattributes` normalising every text file to LF on every platform, so files that are
  bind-mounted or copied into Linux containers (the PostgreSQL init script above all) are
  not broken by a CRLF checkout.
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
  `cap_drop: ["ALL"]` and `no-new-privileges:true` everywhere, every container running as a
  non-root user, dependency ordering via healthchecks. The worker probe is process liveness
  only and makes no readiness claim.
- Multi-stage backend and frontend images, both ending on a non-root `USER`, with matching
  `.dockerignore` files; a hermetic test/lint runner in `docker-compose.test.yml`; an example
  local override file, with `docker-compose.override.yml` itself gitignored.
- PostgreSQL initialisation creating two least-privilege roles, `aegisnet_migrator` and
  `aegisnet_app`. It validates every interpolated role name and secret against a strict
  allowlist and fails closed, and it creates no tables.
- hadolint configuration waiving only DL3006 and DL3008, each with a recorded reason.
- Backend FastAPI application: settings whose secrets are `SecretStr` and which refuse to
  load while any value is still a `.env.example` placeholder outside `ENV=test`; JSON
  logging with correlation-ID propagation, literal-secret scrubbing and control-character
  neutralisation of untrusted values; a single error envelope that discloses no traceback,
  SQL or path; `GET /healthz`; `GET /readyz`; `GET /api/v1/meta/version`.
- Async PostgreSQL engine and async Redis client, connectivity only. A Dramatiq broker
  factory (`adapters/queue/broker.py`) with an explicitly authenticated Redis client and a
  separate worker entrypoint (`adapters/queue/worker.py`) that registers **zero** actors
  (ADR-010), so the worker's topology is proven without inventing a workload.
- `backend/uv.lock`, committed so `uv sync --frozen` and the image build are reproducible.
- Next.js health placeholder for the `web` service: one server-rendered page and
  `GET /api/health`, standalone output, conservative response headers, pinned `pnpm` via
  `packageManager`, committed lockfile. No authentication UI, no business UI (F-9).
- Backend test suite, 124 hermetic tests needing no database or Redis:
  - unit: settings placeholder refusal, `SecretStr` non-disclosure, URL credential escaping,
    log sanitisation (C0/C1, ANSI, CR/LF), secret scrubbing by value and by key name,
    exception records carrying the type only, broker authentication (regression), zero
    actors, `bootstrap_env.py` guarantees;
  - integration: liveness, readiness against faked probes including the timeout path and
    the no-component-detail rule (F-15), version metadata with the git SHA withheld in
    production, interactive docs disabled in production, correlation-ID handling;
  - security: the error envelope leaks nothing (T-2.7); the Compose manifests, both
    Dockerfiles, `.env.example`, `.gitignore` and the pre-commit config satisfy the declared
    policies (T-5.1, T-5.2, T-5.4), read as data.
- `make test`, `test-cov`, `compose-test`, `build`, `up` and `down`. `check` now runs the
  suite after the static checks; `lint`/`format` cover `tests/` too.
- GitHub Actions: `ci.yml` (ruff, ruff format, mypy, pytest with an 85% coverage gate, tsc
  and `next build`, compose config and hadolint, and a `stack` job that runs
  `docker compose up --build --wait` and curls every published endpoint) and `security.yml`
  (gitleaks, pip-audit over the exported uv lockfile, pnpm audit; on push, pull request and
  weekly). On the first push `ci` was green end to end — the stack job reached healthy on
  the runner — and `security` failed on the genuine dependency findings fixed below.

### Changed
- Ruff now also enforces `BLE` (blind `except`). The one intentional broad catch, a failed
  readiness probe, carries an explicit waiver.
- The Dramatiq worker is started with `dramatiq aegisnet.adapters.queue.worker`; the broker
  module is now a side-effect-free factory so it can be imported and tested.
- `README.md`, `docs/STATUS.md` and this file now describe what exists and what has been
  verified locally, with the evidence listed in `docs/STATUS.md`. Earlier revisions claimed
  no application code existed after it had been committed, and referred to tests that had
  not been written.

### Security
- The first `security` workflow run flagged real, known-vulnerable dependencies; both
  findings are fixed by upgrade, verified by a clean local `pip-audit --strict` and
  `pnpm audit --prod --audit-level=high`, with the suite unchanged at 124 passed:
  - starlette 0.46.2 (pulled in by the fastapi `<0.116` pin) carried nine advisories.
    fastapi moves to 0.141, uvicorn to 0.52, and a `constraint-dependencies` entry bars the
    resolver from any starlette below 1.3.1 (now 1.6.0). The two status-code constants
    starlette renamed are updated (`HTTP_413_CONTENT_TOO_LARGE`,
    `HTTP_422_UNPROCESSABLE_CONTENT`); the wire format is unchanged.
  - next 14.2.35 carried ten high advisories patched only in the 15.5 line. The web
    placeholder moves to next 15.5.24 with react 19, and a pnpm override forces the
    bundled postcss to ≥8.5.18 (next still pins 8.4.31, which has two high advisories).
- The `web` image base moves from `node:20-alpine` (end of life April 2026) to
  `node:22-alpine`, matching the CI node version.

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
  "no inline secret literals" policy test covers every Compose file, including this one.
- The worker never authenticated to Redis. `RedisBroker(url=..., password=...)` builds its
  own connection pool from the URL and redis-py ignores `password` when a pool is supplied,
  so the first Redis command would have failed with `NOAUTH`. The broker now receives an
  explicitly authenticated client, and a regression test pins the connection arguments.
- The worker liveness probe always passed: `pgrep -f 'dramatiq …'` matched the `sh -c`
  wrapper running the probe, whose command line contains the pattern. The pattern is now
  `[d]ramatiq …`, which cannot match itself.
- The stack could not start. Under `cap_drop: ALL` the official `postgres` and `redis`
  images fail to drop from root to their service user (`setresuid failed: Operation not
  permitted`) and restart-loop. Both services are now started directly as that user via
  `user:`, keeping the capability drop intact. This was the first time the stack was started;
  every service now reports healthy.
- CRLF checkouts on Windows made `infra/postgres/init/01_roles.sh` unusable when
  bind-mounted into the database container; fixed by `.gitattributes`.

### Not yet present
Database migrations, ORM models, Suricata EVE schemas and normalisation, ingestion
endpoints, dataset registry, background actors, asset and event APIs, authentication, RBAC,
audit logging, rate limiting, detectors, correlation, Perplexity integration, reports,
dashboard, `SECURITY.md`.
