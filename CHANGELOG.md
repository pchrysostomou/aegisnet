# Changelog

All notable changes to AegisNet are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Nothing is released yet. There is no tagged version.

## [Unreleased]

### Added
- **Chunk 10 (Milestone 2) — D-002 auth-failure burst and D-003 DNS anomaly.**
  `domain/detectors/auth_burst.py`: Suricata alerts whose signature or category reads like an
  authentication failure, tallied per source; fires on the count only when the densest
  two-minute span holds the whole threshold, so a steady monitoring probe never trips it.
  `domain/detectors/dns_anomaly.py`: per querying client (answers attributed to their
  destination), three signals with separate thresholds: many high-entropy names under one
  base domain, an NXDOMAIN storm by count and share, a stream of over-long labels; CDN and
  cloud suffixes allow-listed. Both registered, so every sweep runs three rules.
- Thirteen labelled cases (three positives and four hard negatives for D-002, three and
  three for D-003) rendered by `tools/gen_labelled_fixtures.py`, which gained `alert` and
  `dns` record builders; specifications, guards and limitations in `docs/detection-rules.md`;
  28 new detector tests.
- **Chunk 9 (Milestone 2) — the sweep, alert storage and the alerts API.** Revision
  `0003_detection_tables` (`detection_rules`, `detector_runs`, `alerts` with a UNIQUE
  `dedup_key`, `alert_events`, `alert_assets`, `asset_baselines`; six enum types; runtime
  role SELECT/INSERT/UPDATE, no DELETE). `services/detection_service.py`: registry synced
  from code, one bounded load per interval sliced on each rule's `window_seconds` grid,
  severity from the resolved asset's criticality with a stored rationale, dedup at the
  database, one `detector_runs` row per rule with per-rule failure isolation (ADR-018).
  `adapters/db/detection_store.py`, the `EventWindowStore` loader on the event read store,
  the `run_detectors` actor on the `detection` queue, CLI `run-detectors`, `alerts`,
  `alert`, `detector-runs`, `make run-detectors`, `make alerts`.
- Routes `GET /api/v1/alerts`, `GET /api/v1/alerts/{id}`, `GET /api/v1/detections/rules`,
  `GET /api/v1/detections/runs`, `POST /api/v1/detections/sweeps` with the permissions
  `alerts.read` (viewer), `detections.read` (analyst), `detections.run` (admin);
  `docs/api-milestone-2.md`. The CI stack job queues a sweep over HTTP and waits for the
  worker's `success` run. 54 new hermetic tests and 3 database tests (the stores, and the
  sweep end to end over an ingested labelled fixture).
- **Chunk 8 (Milestone 2) — the detector contract and D-001 port scan.**
  `domain/detectors/`: `EventWindow` (aware, sorted, at most 24 h and 200 000 events, every
  event inside the window), `DetectionResult` with evidence bounded at construction (no raw
  line can travel in it), `Entity`, sampled event ids, the `dedup_key`
  `rule_id:entity=value:window_bucket`, `RuleSpec`, the `Detector` Protocol; `severity.py`
  with the recorded formula and `reproduce`; the in-process registry; `PortScanDetector`
  counting distinct `(host, port)` targets per source with inclusive thresholds, unanswered
  flows raising confidence (ADR-017, `docs/detection-rules.md`).
- `tools/gen_labelled_fixtures.py` and seven labelled D-001 cases (three positive, four
  negative incl. the backup-client hard negative) under `backend/tests/fixtures/labelled/`,
  pinned byte for byte by a test; `make test-detectors`, `make gen-fixtures`; 38 detector
  tests (bounds, severity, D-001 behaviour and purity, registry, every labelled case).
- **Chunk 7 — the documents at the Milestone 1 gate.** A `dataset_id` that fails its grammar
  on `POST /api/v1/ingest/import` is now audited as `ingest.refused` with the caller and the
  field name (never the value), which closes the last API acceptance criterion. The
  delivery plan's M1 acceptance boxes point at their evidence; `ARCHITECTURE.md` gained an
  implementation-status section and reflects the M1 topology; `THREAT_MODEL.md` carries the
  gate review; `docs/evaluation.md` states that no detector exists and accuracy is
  unmeasured; `docs/STATUS.md` reconciles the Definition-of-Done checklist.
- **Chunk 6 — authentication, RBAC, audit, rate limits and the HTTP routes.**
  `domain/auth.py`: the permission set, the role matrix (`viewer ⊂ analyst ⊂ admin`,
  `ingest_service` = ingest + version), principals, the length-only password policy,
  opaque tokens stored as sha256. `services/auth_service.py`: Argon2id users, login with
  generic failures, timing equalisation and lockout, HS256 access tokens verified against
  the service clock, rotating refresh tokens with reuse detection that revokes the chain,
  logout with a Redis `jti` denylist, service tokens with expiry and revocation.
  `services/audit_service.py`: bounded, credential-free audit detail. `api/deps.py`: the
  deny-by-default `require(permission)` dependency, rate-limit dependencies and the
  `AppServices` factory injection (ADR-016).
- HTTP routes: `/api/v1/auth/{login,refresh,logout,me}`, `/api/v1/ingest/eve` (NDJSON
  body or multipart, `mode=sync|async` through a capped spool), `/api/v1/ingest/import`,
  `/api/v1/ingest/batches[/{id}[/rejects]]`, `/api/v1/assets` (create, bulk, resolve,
  list, get, patch, deactivate), `/api/v1/events[/stats|/{id}]`, `/api/v1/audit`.
  Response DTOs in `api/schemas.py`; new error codes `unauthenticated` (with
  `WWW-Authenticate: Bearer`), `invalid_credentials`, `forbidden`, `rate_limited` (with
  `Retry-After`), `payload_too_large`.
- Adapters: `adapters/db/auth_store.py` (users, refresh tokens, service tokens),
  `adapters/db/audit_store.py`, `adapters/cache/rate_limiter.py` (fixed-window limiter and
  token denylist on Redis), `adapters/files/spool.py`; the `import_upload` worker actor
  finishes an async upload from the spool; Compose gains the `ingest_spool` volume shared
  by `api` and `worker` only.
- CLI: `create-user` (password from stdin), `users`, `create-service-token` (printed
  once), `revoke-service-token`, `service-tokens`; Makefile targets `create-user`,
  `users`, `create-service-token`, `revoke-service-token`, `service-tokens`.
- `SECURITY.md`: the credential model, the RBAC matrix, the audit actions, the rate-limit
  policy, ingest hardening, known gaps and disclosure.
- 184 new hermetic tests (auth domain and service, audit service, Redis adapters on
  fakeredis, spool, CLI, the RBAC route-enumeration and 19 × 4 matrix suite, route
  integration for auth, ingest, assets, events and audit) and 5 database tests (SQL auth
  and audit stores, the auth service end to end on PostgreSQL). The `stack` CI job now
  creates a user and a service token through the CLI, proves the unauthenticated `401`,
  ingests the synthetic corpus over HTTP and reads the finished batch and the audit trail.
- **Chunk 5 — asset inventory and event reads.** `domain/assets.py`: validated
  `AssetSpec`/`AssetPatch` (hostname grammar, tags, criticality 1–5, strict CIDRs, one
  primary network), cross-asset overlap detection and the reference `resolve_ip`
  (longest prefix, then primary, then oldest). `services/asset_service.py`: create, bulk
  create (atomic, ≤500), upsert-by-hostname seeding, get, filtered keyset-paginated list,
  partial update that replaces networks, soft-delete, resolve. `services/
  event_read_service.py`: window ≤30 days, page size ≤200, cursor validation, payload on
  request only; `stats` by type and hour. Batches and rejects are listable with cursors
  (ADR-015).
- `domain/pagination.py`: opaque base64url keyset cursors, strictly validated (T-2.6).
- SQL stores `adapters/db/asset_store.py` (resolution as an `ORDER BY`, hostname
  uniqueness mapped to `HostnameConflictError`) and `adapters/db/event_read_store.py`
  (keyset on `(event_time, id)`, address/CIDR/port/flow/batch/asset filters, stats).
- Revision `0002_asset_network_delete_grant`: the runtime role may DELETE from
  `asset_networks` so a PATCH can replace them; nothing else gains DELETE.
- Seed file `samples/assets/lab-assets.yml` (14 lab hosts matching the synthetic corpus)
  and `make seed`; CLI commands `seed-assets`, `assets`, `asset`, `resolve`, `events`,
  `event-stats`, `batches`, `rejects`.
- 94 new hermetic tests (domain rules, cursors, both services against fakes, CLI parsing
  and the seed loader, the T-2.6 pagination-bounds suite) and 15 database tests (the
  asset store incl. resolution precedence and atomic bulk create; the event read store
  incl. a full pagination walk, the asset filter, stats; batch and reject listing).
- **Chunk 4 — ingest service.** `services/ingest_service.py` streams NDJSON line by line
  through the normaliser, writes events in chunks with `INSERT … ON CONFLICT (event_hash)
  DO NOTHING` so a re-ingest stores nothing and reports every line as a duplicate, writes
  one `ingest_rejects` row per bad line, and records counts, provenance and outcome on the
  batch. Exceeding `INGEST_MAX_LINES` marks the batch `failed` and keeps the valid events
  already stored; a bad line never fails a batch (ADR-014).
- `domain/ports.py` (the `IngestStore` Protocol and the batch value objects),
  `adapters/db/ingest_store.py` (SQLAlchemy implementation, running as the runtime role)
  and `adapters/db/session.py`.
- The first Dramatiq actor, `import_dataset`, in the new entrypoint layer
  `aegisnet.workers` (`dramatiq aegisnet.workers.main`). Messages carry ids only and are
  enqueued by actor name through `adapters/queue/ingest_queue.py`; the actor does not retry.
- Operator CLI `python -m aegisnet.cli` (`datasets`, `import-dataset --mode sync|async`,
  `batch`); `make demo-ingest` (`DATASET=`, `LABEL=`, `MODE=`) and `make batch ID=` run it
  inside the api image. The HTTP ingest routes ship together with authentication in
  Chunk 6.
- Settings for the ingest limits and `SAMPLES_DIR` (documented in `.env.example`);
  `./samples` bind-mounted read-only into `api` and `worker`; `worker` now depends on `db`
  as well as `redis`.
- import-linter layers are now entrypoints (`api | workers | cli`) over `services` over
  `adapters` over `domain`.
- 25 new hermetic tests (the service against an in-memory store: counts, chunking,
  intra-batch duplicates, the line budget, storage failure, provenance from the registry;
  CLI usage) and 5 database tests (idempotent corpus import matching the manifest, the
  provenance row, persisted rejects, promoted columns, and the actor end to end through a
  `StubBroker`).
- **Chunk 3 — EVE domain and synthetic corpus.** `domain/eve/`: parse limits enforced
  before parsing (byte cap, bracket-depth scan of the raw text, then depth, key and item
  counts on the parsed shape), a sanitiser that strips C0/C1 control characters and caps
  every string and key, a Pydantic schema for the EVE common fields and the `alert`, `dns`,
  `http`, `flow`, `tls`, `fileinfo`, `anomaly` and `ssh` sub-objects with unknown keys kept,
  a versioned canonical `event_hash`, and a pure, clock-free normaliser producing
  `NormalizedEvent` or a `Reject` carrying one of the seven documented reason codes and no
  input value (ADR-013). `domain/models.py` holds the frozen value objects.
- `adapters/files/registry.py`: `samples/registry.yml` loader and dataset resolution by id
  only — relative path confined under `samples/`, symlinks refused at every component,
  sha256 verified before a byte is read, and error messages free of paths (T-1.6).
- `tools/gen_synthetic_eve.py`, a standard-library, seeded generator; the committed corpus
  `samples/synthetic/benign-baseline-01.ndjson` (2000 events, 937 KB, RFC 1918/5737
  addresses and example.test/example.com names only) with its manifest, registered in
  `samples/registry.yml`; `samples/README.md`; `make gen-synthetic`.
- import-linter contracts (`domain` imports no infrastructure; `api` over `adapters` over
  `domain`), run by `make lint` and the CI backend job. Ruff and the pre-commit hooks now
  also cover `tools/`.
- 125 new hermetic tests: sanitiser, limits, schema, hash and normaliser over hand-built
  benign and hostile fixtures (`backend/tests/fixtures/eve/`), payload-limit and
  path-traversal security suites, generator determinism and safety, and an integrity test
  tying the committed corpus, its manifest and the registry checksum together.
- **Chunk 2 — schema baseline.** Alembic revision `0001_m1_baseline` creates the nine
  Milestone 1 tables from `docs/data-model.md` (`users`, `service_tokens`, `refresh_tokens`,
  `audit_log`, `ingest_batches`, `events`, `ingest_rejects`, `assets`, `asset_networks`),
  nine PostgreSQL enum types, every documented index including `UNIQUE (event_hash)`,
  `GIST (cidr inet_ops)`, `GIN (payload jsonb_path_ops)` and the partial indexes, and
  check constraints for hash lengths, port ranges, criticality and text caps. It runs as
  the migrator role and grants the runtime role `SELECT, INSERT, UPDATE` on the ordinary
  tables, `SELECT, INSERT` on `audit_log` plus `USAGE` on its identity sequence, and
  `SELECT` on `alembic_version`; no `DELETE` anywhere and no DDL (T-2.5, T-5.3).
  `audit_log` has no foreign keys so no referential action can rewrite it. The migration
  environment ships inside the package (`adapters/db/migrations/`), `alembic.ini` carries
  no URL, and `env.py` reads the migrator credentials from `Settings.migration_url`
  (ADR-012).
- SQLAlchemy 2.0 models for the same nine tables (`adapters/db/models.py`) and the schema
  enumerations in `domain/enums.py`, the first module of the pure domain layer.
- `schema_revision()` in `version.py` reads the head of the packaged revisions;
  `/api/v1/meta/version` now reports it (`0001_m1_baseline`).
- `make migrate` (`alembic upgrade head` inside the api image), `make migrate-status`, and
  `make test-db`, which runs the new database suite against an ephemeral PostgreSQL 16
  started from `docker-compose.test.yml --profile db` (`db-test`, `tests-db`; decision F-2)
  and tears it down afterwards. The hermetic `tests` service is unchanged.
- Database suite `backend/tests/db/` (marker `db`, opt-in via `AEGISNET_DB_TESTS=1`):
  the nine tables and nothing else, `alembic_version` equals the packaged head, Alembic's
  `compare_metadata` reports no difference between the models and the migrated schema,
  enum labels, specialised index definitions, the `event_hash` length and uniqueness
  constraints, case-insensitive `users.email` (citext), server-side defaults, the runtime
  role's exact privilege matrix and table ownership, refusal of UPDATE/DELETE/TRUNCATE on
  `audit_log` and of every DDL and DELETE statement, and a head → base → head round trip
  that leaves nothing behind.
- CI job `migrations` runs that suite on every push; the `stack` job now applies the
  migrations with `alembic upgrade head` inside the started stack and asserts the version
  endpoint reports the head.
- The init script grants the migrator `CREATE` on the database so a revision can install
  the trusted `citext` extension; the runtime role never receives it.
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
- The version route reports `0003_detection_tables`; the stack probe and the README expect it.
- README rewritten for the public repository: architecture diagrams (topology, layering,
  the upload pipeline, request handling), the RBAC matrix, a repository map, the roadmap,
  workflow and quality-gate badges. `CONTRIBUTING.md` and a pull-request template added;
  the repository is public with topics, Dependabot alerts, secret scanning and push
  protection enabled.
- `Spool.write(name, chunks, max_bytes)` takes a caller-minted name (`Spool.new_name()`)
  and returns the byte count; `Spool.lines(name)` reads an entry asynchronously. The
  ingest route mints the name before it reads the body. `anyio` is a direct dependency.
- `.sonarcloud.properties` declares the source roots and `backend/tests` as tests for
  SonarCloud automatic analysis, so ratings reflect main code (E-39).
- `/api/v1/meta/version` requires a credential (`meta.read`); the CI stack probe and the
  README quickstart obtain a service token first (Chunk 6).
- `IngestService.ingest` accepts a pre-opened `batch_id` so the worker can finish a batch
  the API opened; `bounded_detail` keeps one level of nested mapping (Chunk 6).
- The hermetic coverage gate now also excludes the SQL stores and the worker package,
  which the database suite and the stack exercise; both results are recorded in
  `docs/STATUS.md`.
- The worker entrypoint moved from `adapters/queue/worker.py` to `aegisnet.workers.main`;
  the Compose `worker` command and liveness probe follow. `adapters/queue` keeps the broker
  factory plus the queue and actor names (ADR-014).
- Request-derived text is neutralised at the sink, not only by the log formatter.
  `untrusted_text` strips CR and LF explicitly, then every other control character, and
  truncates; `safe_value` delegates to it for strings. The unhandled-exception log call
  passes the request path and method through it, and the correlation-ID middleware
  re-renders the inbound id from the parsed UUID and passes it through the same strip
  before echoing it in the response header (`canonical_correlation_id`). Behaviour is
  unchanged; the guard is now visible at each sink to a reader and to static taint
  analysis. Prompted by the SonarCloud quality gate, which has failed on *Security Rating
  on New Code C* since its first analysis; the project is private on sonarcloud.io and the
  check exposes no finding, so this addresses the two flows its Python taint rules cover.
- GitHub Actions: every action moves to a release that runs on the Node 24 runtime
  (`actions/checkout` v6, `actions/setup-node` v7, `actions/upload-artifact` v7,
  `gitleaks/gitleaks-action` v3, `astral-sh/setup-uv` v10.0.1). Every job of both workflows
  was annotated "Node.js 20 is deprecated", and GitHub removes Node 20 from hosted runners
  on 2026-09-16, after which the previous majors would not run at all. `setup-uv` publishes
  no major tags from v8 on and is pinned to an exact release. The `hadolint` action is a
  Docker action and is unaffected.
- Ruff now also enforces `BLE` (blind `except`). The one intentional broad catch, a failed
  readiness probe, carries an explicit waiver.
- The Dramatiq worker is started with `dramatiq aegisnet.adapters.queue.worker`; the broker
  module is now a side-effect-free factory so it can be imported and tested.
- `README.md`, `docs/STATUS.md` and this file now describe what exists and what has been
  verified locally, with the evidence listed in `docs/STATUS.md`. Earlier revisions claimed
  no application code existed after it had been committed, and referred to tests that had
  not been written.

### Security
- The echoed `X-Correlation-ID` is rebuilt from the parsed UUID's integer, never from the
  inbound string; the unhandled-error log records the matched route template and a
  fixed-set method instead of the request path and method (E-40).
- Chunk 6: no route answers without a permission dependency; a present-but-invalid
  credential is `401`, never anonymous; refresh-token reuse revokes the chain and clears
  the cookie; refused uploads and permission denials are audited; login and ingest rate
  limits fail closed when Redis is unavailable; passwords never appear in argv and tokens
  are stored only as hashes (ADR-016, `SECURITY.md`).
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
- The last SonarCloud quality-gate condition (*Security Rating on New Code C*): a
  redundant `Path.chmod` after creating `.env` with mode 0600 in `bootstrap_env.py`,
  located by bisecting the analysis scope (E-41). The gate passes.
- Dependabot GHSA-6w46-j5rx-g56g: pytest upgraded to 9.x (with pytest-asyncio 1.x); both
  suites unchanged.
- Sonar `python:S7493` (a synchronous `Path.open()` inside an `async def`) in the dataset
  importer and the upload actor, the two Major bugs behind the *Reliability Rating on New
  Code C*: NDJSON is now read through `anyio` and `IngestService.ingest` accepts a sync or
  async line source (E-39).
- The `ingest_spool` named volume was mounted root-owned while the api and worker run as
  uid 10001, so the first HTTP upload failed with `500`. The image now creates `/app/spool`
  owned by the runtime user (a named volume inherits it on first use) and both processes
  run `Spool.ensure_writable()` at startup so a wrong mount fails loudly, not per request
  (Chunk 6, E-37).
- The `security` workflow's pip-audit job used the same uv cache key as the `ci` backend
  job. Finishing first, it saved a cache that held only pip-audit's own dependencies, so the
  backend job could never save the runtime set it had just installed; setup-uv v10 surfaces
  this as "Unable to reserve cache". The pip-audit job now runs with the cache disabled.
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
