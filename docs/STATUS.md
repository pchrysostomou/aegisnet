# AegisNet — Project Status

**Last updated:** 2026-08-30 · **Current phase:** M1 Chunk 1 (foundation) verified locally; CI not yet run · **Version:** none tagged

> This file is the single source of truth for progress. It states only what has **evidence**. Nothing below is
> claimed to run, pass, or exist unless an evidence entry is given.

---

## Current state

| | |
|---|---|
| Phase | **M1 — Chunk 4 (ingest service, first actor, CLI demo path) complete and verified locally; Chunk 5 (assets and events) not started** |
| Application code written | Settings, JSON logging, error envelope, `/healthz`, `/readyz`, `/api/v1/meta/version`, DB/Redis connectivity adapters, Dramatiq broker with zero actors; Alembic baseline `0001_m1_baseline` for the nine M1 tables, ORM models, schema enums in `domain/`, `schema_revision()` (ADR-012); EVE domain — limits, sanitiser, schema, canonical hash, normaliser — dataset registry adapter, synthetic generator and committed corpus (ADR-013); ingest service, SQL ingest store, `import_dataset` actor in the `workers` layer, operator CLI (ADR-014) |
| Frontend | Health placeholder: one page, `GET /api/health` |
| Tests written | 287 hermetic (unit, integration, security) plus 24 database tests (marker `db`, opt-in, real PostgreSQL) |
| Tests run | **Yes, locally** — hermetic suite E-24; database suite E-25 (native) and E-26 (Compose); stack demo E-27 |
| Docker stack | **Built and started locally; all five services healthy** — see evidence E-3 |
| Database | Roles `aegisnet_migrator` / `aegisnet_app` created at init; **nine tables created by `make migrate`** under the migrator role, runtime-role privileges proven exact by the database suite (E-18); `/api/v1/meta/version` reports the packaged head |
| Perplexity integration | **Not implemented; no API call has been made** |
| CI | `ci` **green** end to end, including the stack job (E-10, E-13). `security` failed on real findings on the first push (E-11), fixed by dependency upgrades (E-12), **green** since (E-13). Every job carried a Node 20 deprecation annotation; cleared by moving to Node 24 action releases (E-15) |
| SonarCloud | External GitHub App check (automatic analysis, not a workflow in this repository). **Quality gate failed** on every analysis since the first; single failing condition *Security Rating on New Code C*. Finding not readable from the check (E-17) |
| Detector accuracy | **Unmeasured. No claims.** |

## Evidence (local, 2026-08-30, Windows 11 host, Docker Desktop 29.7 / Compose v5.4)

| ID | Command | Result |
|---|---|---|
| E-1 | `cd backend && ENV=test uv run pytest` | `124 passed` |
| E-2 | `ENV=test uv run pytest --cov=aegisnet` | 96% line+branch coverage; only `worker.py` (import-time entrypoint) and the real DB/Redis round trips are uncovered |
| E-3 | `make bootstrap && docker compose up -d --wait --wait-timeout 240` | `db`, `redis`, `api`, `worker`, `web` all `(healthy)`; `api` on `127.0.0.1:8000`, `web` on `127.0.0.1:3000`, no other port published |
| E-4 | `curl 127.0.0.1:8000/healthz`, `/readyz`, `/api/v1/meta/version`, `127.0.0.1:3000/api/health` | all `200`; readiness `{"status":"ok"}`; response carries `x-correlation-id` |
| E-5 | `docker compose exec <svc> id` for every service | `db` uid 70, `redis` uid 999, `api`/`worker` uid 10001, `web` uid 1000 — no root |
| E-6 | `docker compose exec worker python -c "...build_broker(get_settings()).client.ping()"` | `True` (worker authenticates to the `--requirepass` Redis); declared actors `[]` |
| E-7 | `psql` as `aegisnet_app`: `CREATE TABLE` | `permission denied for schema public`; the same statement as `aegisnet_migrator` succeeds |
| E-8 | `uv run ruff check src tests`, `ruff format --check`, `mypy` | clean |
| E-9 | `docker compose -f docker-compose.test.yml run --rm --build tests` | `124 passed` inside the non-root `dev` image, with no secret variable set and unresolvable datastore hostnames |
| E-10 | GitHub Actions `ci` run **33331753840** (first push) | ✅ all four jobs, including `stack`: `docker compose up --build --wait` reached healthy on the runner and every published endpoint answered |
| E-11 | GitHub Actions `security` run **33331753793** (first push) | ❌ genuine findings: starlette 0.46.2 carried 9 advisories (via the fastapi pin) and next 14.2.35 carried 10 high (patched in ≥15.5.21, plus bundled postcss 8.4.31) |
| E-12 | After upgrading (fastapi 0.141 → starlette 1.6.0, uvicorn 0.52; next 15.5.24, react 19, postcss override): `uvx pip-audit --strict` on the exported lockfile and `pnpm audit --prod --audit-level=high` | both clean locally; `124 passed` unchanged |
| E-13 | GitHub Actions `security` runs **33332243302** (push, 2026-08-30) and **33399756070** (weekly schedule, 2026-08-31) | ✅ gitleaks, pip-audit and pnpm audit all clean on the runner |
| E-14 | 2026-09-04, macOS host: `uvx pip-audit --strict` on the exported lockfile, `pnpm audit --prod --audit-level=high`, `ruff check`, `ruff format --check`, `mypy`, `ENV=test uv run pytest`, `pnpm typecheck` | all clean against that day's advisory data; `124 passed` |
| E-15 | Annotations on every job of runs 33332243290 (`ci`) and 33399756070 (`security`) | ⚠️ "Node.js 20 is deprecated … forced to run on Node.js 24" for `checkout@v4`, `setup-node@v4`, `upload-artifact@v4`, `setup-uv@v5`, `gitleaks-action@v2`; GitHub removes Node 20 from hosted runners on 2026-09-16. Fixed by moving each to a Node 24 release; the result is recorded on the push that carries it |
| E-16 | Push a8e9510 (Node 24 actions): `security` run **33918434907**, `ci` run **33918434915** | ✅ both green, no Node 20 annotation. One new annotation on the `ci` backend job: "Failed to save: Unable to reserve cache … another job may be creating this cache" — the `security` pip-audit job had saved a 7.9 MiB cache under the shared key first. Fixed by disabling the cache in that job and deleting the stale entry. Verified on push e712429: `security` run **33918817419** and `ci` run **33918817392** both green with no annotation, and the backend job saved a 41 MiB cache (the runtime set) under its key |
| E-18 | 2026-09-05, macOS host, native PostgreSQL 16.15 (Homebrew) initialised with `infra/postgres/init/01_roles.sh`: `AEGISNET_DB_TESTS=1 uv run pytest -m db -v` | `19 passed`: the nine tables and nothing else; `alembic_version` equals the packaged head; Alembic `compare_metadata` reports **no** difference between `models.py` and the migrated schema; enum labels; GIST `inet_ops`, GIN `jsonb_path_ops`, partial and DESC index definitions; `event_hash` 32-byte check and uniqueness; case-insensitive `users.email`; server-side defaults; app-role privilege matrix exactly `SELECT, INSERT, UPDATE` on the ordinary tables, `SELECT, INSERT` on `audit_log`, `SELECT` on `alembic_version`; the migrator owns every table; UPDATE/DELETE/TRUNCATE on `audit_log`, DELETE on every table, and CREATE/ALTER/DROP/CREATE EXTENSION all refused; head → base → head round trip leaves only the empty `alembic_version` |
| E-19 | 2026-09-05: `ruff check`, `ruff format --check`, `mypy`, `ENV=test uv run pytest --cov=aegisnet --cov-fail-under=85` | clean; `137 passed, 19 skipped`; coverage 98% (the migration environment is excluded from the hermetic gate and exercised by E-18 instead, ADR-012) |
| E-20 | 2026-09-05, macOS host, Docker Desktop 29.4 / Compose v5.1: `make test-db`, then `make up && make migrate && make migrate-status`, probes, `make down` | ✅ Compose path: `db-test` healthy, `tests-db` `19 passed`, teardown clean. Stack path: all five services healthy; `alembic upgrade head` ran inside the api image as the migrator; `alembic current` and `heads` both `0001_m1_baseline (head)`; `/readyz` `{"status":"ok"}`; `/api/v1/meta/version` carries `"schema_revision":"0001_m1_baseline"`; `\dt` as `aegisnet_app` lists the nine tables plus `alembic_version`, every one owned by `aegisnet_migrator`; `UPDATE audit_log` as `aegisnet_app` → `permission denied for table audit_log`. (Docker Desktop first hung on image pulls for most of the session and needed a forced restart; the native run E-18 preceded this.) |
| E-22 | 2026-09-05: `ruff check` (backend and `tools/`), `ruff format --check`, `mypy` (strict on `domain/`), `lint-imports`, `ENV=test uv run pytest --cov=aegisnet --cov-fail-under=85` | clean; both import contracts kept; `262 passed, 19 skipped`; coverage 98%, every `domain/eve` module 100%. `python3 tools/gen_synthetic_eve.py` regenerates the committed corpus byte-identically (sha256 `5f1c7bd2…`, recorded in `samples/registry.yml` and verified by `tests/integration/test_samples_corpus.py`) |
| E-24 | 2026-09-05: `ruff check` (backend, `tools/`), `ruff format --check`, `mypy` (43 files, strict on `domain/`), `lint-imports`, `ENV=test uv run pytest --cov=aegisnet --cov-fail-under=85` | clean; both contracts kept (entrypoints over services over adapters over domain); `287 passed, 24 skipped`; coverage 92% (the CLI wiring and the worker actor are exercised by the database suite and the stack, not the hermetic gate) |
| E-25 | 2026-09-05, native PostgreSQL 16.15: `AEGISNET_DB_TESTS=1 uv run pytest -m db -v` | `24 passed`: the committed corpus imports with counts equal to its manifest (2000 stored), a second import stores 0 and reports 2000 duplicates, the batch row carries method/dataset/licence/timestamps, hostile lines persist as rejects with line numbers and reason codes, promoted columns match the normaliser, and `import_dataset` runs end to end through a `StubBroker` against a pre-opened batch |
| E-26 | 2026-09-05, Docker Desktop 29.4 / Compose v5.1: `make test-db` | ✅ `24 passed` inside `tests-db` against `db-test`, teardown clean |
| E-27 | Same day: `make up && make migrate`, then the CLI inside the api image: `import-dataset synthetic-benign-baseline-01` (sync) twice, once more with `--mode async`, `batch <id>` polled, worker log read, `make down` | ✅ first run `stored 2000, duplicate 0`; second run `stored 0, duplicate 2000`; the async run returned `{"status": "received", "message_id": …}` at once and the worker finished it two seconds later (`worker_started … "actors_registered": ["import_dataset"]`, then `ingest_batch_finished` and `import_dataset_done` with `duplicate 2000`); `SELECT count(*) FROM events` as the app role = 2000 across three `complete` batches; stack torn down |
| E-28 | Push b8791bc (Chunk 4): GitHub Actions `ci` run **33953478893** and `security` run | ✅ all five `ci` jobs green with no annotation — `migrations` now includes the ingest store tests and the actor through a `StubBroker` (45s), `stack` migrates and probes (1m46s); `security` green. SonarCloud unchanged: *Quality Gate failed* on the same single condition (E-17) |
| E-23 | Push cae5d5d (Chunk 3): GitHub Actions `ci` run **33952182281** and `security` run **33952182289** | ✅ all five `ci` jobs green with no annotation, including the backend job's new `lint-imports` step and ruff over `tools/`; `security` green. SonarCloud unchanged: *Quality Gate failed* on the same single condition (E-17) |
| E-21 | Push 2d3a437: GitHub Actions `ci` run **33950753099** and `security` run **33950753033** | ✅ all five `ci` jobs green with no annotation — `backend`, `frontend`, `manifests`, **`migrations` (upgrade, grants, downgrade on PostgreSQL 16, 32s)** and **`stack` (compose up --build reaches healthy, migrate, 1m53s)**; `security` green. SonarCloud still reports *Quality Gate failed* on the same single condition (E-17) |
| E-17 | SonarCloud Code Analysis check (`sonarqubecloud` app) on 9ef3024, 89f8dae, a8e9510, e712429, fc53775 | ❌ every one "Quality Gate failed"; the only failing condition is **Security Rating on New Code C** (required A). The project is private on sonarcloud.io, the check carries no annotation and no notification e-mail exists, so the exact finding could not be read. The two request-derived flows Sonar's Python taint rules cover are now neutralised at the sink (`untrusted_text` in the unhandled-exception log call; `canonical_correlation_id` before the response header); 135 tests, 96% coverage. Result recorded on the push carrying it |

## Milestone tracker

| Milestone | Status | Evidence | Notes |
|---|---|---|---|
| M0 Planning | ✅ Complete | This doc set | PRD, architecture, threat model, data model, M1 API, delivery plan, evaluation plan |
| M1 Foundation / ingest / normalize / assets | 🟡 In progress — Chunks 1–4 done | E-1 – E-8, E-18 – E-28 | Next: Chunk 5 assets and events |
| M2 Five detectors + labelled fixtures | ⬜ Not started | — | Blocked on M1 |
| M3 Correlation / incidents / workflow | ⬜ Not started | — | Blocked on M2 |
| M4 Analyst dashboard | ⬜ Not started | — | Blocked on M3 |
| M5 Perplexity brief + Markdown export | ⬜ Not started | — | Blocked on M4 (safe renderer first) |
| M6 Hardening / evaluation / release | ⬜ Not started | — | Gate for `v1.0.0` |

## Milestone 1 chunk tracker

| Chunk | Contents | Status |
|---|---|---|
| 1 | Skeleton, Compose, config, logging, health, worker topology, web placeholder, tests, CI | ✅ Locally verified |
| 2 | Alembic baseline migration, ORM models, DB grants incl. `audit_log` | ✅ Verified locally (native E-18, Compose and stack paths E-20) and in CI (E-21) |
| 3 | EVE domain: schema, sanitizer, normalizer, `event_hash`, synthetic generator, registry | ✅ Verified locally (E-22) and in CI (E-23) |
| 4 | Ingest service, first Dramatiq actor, rejects, idempotency | ✅ Verified locally (E-24 – E-27) and in CI (E-28) |
| 5 | Assets API, events read API | ⬜ |
| 6 | Auth, RBAC, audit, rate limits, `SECURITY.md` | ⬜ |
| 7 | Docs update at the M1 gate with CI evidence | ⬜ |

## Definition-of-Done checklist (v1.0.0)

- [ ] `docker compose up --build` starts the full local environment — *Chunk 1 topology does (E-3); the full environment does not exist yet*
- [x] Documented safe sample dataset ingests via one command — `make demo-ingest` (Chunk 4; E-27: second run adds zero events)
- [ ] All five detectors have labelled positive **and** negative test cases
- [ ] Unit + integration tests run in GitHub Actions
- [ ] A reviewer reproduces the main demo from the README alone
- [ ] Architecture, threat model, evaluation results, limitations, screenshots, demo script all exist
- [ ] Auth, RBAC, audit logging, rate limiting implemented and tested
- [ ] Redaction canary suite proves no forbidden data reaches Perplexity
- [ ] `docs/RELEASE_CHECKLIST.md` complete and signed off

## Documents

| Doc | State |
|---|---|
| `README.md` | ✅ Reflects Chunk 1 |
| `ARCHITECTURE.md` | ✅ v0.1 (proposal) |
| `THREAT_MODEL.md` | ✅ v0.1 (planning-phase model; review at every milestone gate) |
| `SECURITY.md` | ⬜ Chunk 6 (RBAC matrix, secret handling, disclosure policy) |
| `docs/PRD.md` | ✅ v0.1 |
| `docs/repo-structure.md` | ✅ v0.1 |
| `docs/data-model.md` | ✅ v0.1 |
| `docs/api-milestone-1.md` | ✅ v0.1 |
| `docs/delivery-plan.md` | ✅ v0.1 |
| `docs/evaluation.md` | ✅ v0.1 plan; **results empty by design** |
| `samples/README.md` | ✅ Chunk 3: datasets, registry fields, how a file is imported |
| `docs/detection-rules.md` | ⬜ M2 |
| `docs/perplexity-integration.md` | ⬜ M5 |
| `docs/demo-script.md` | ⬜ M6 |
| `docs/RELEASE_CHECKLIST.md` | ⬜ M6 |

## Decisions locked in M0

| ID | Decision |
|---|---|
| D-1 | Background work: **Dramatiq + periodiq** (rationale in `ARCHITECTURE.md` §2) |
| D-2 | Modular monolith backend, strict pure `domain/` layer enforced by import-linter |
| D-3 | Deterministic heuristic detectors only in v1; no ML |
| D-4 | Suricata EVE JSON only in v1; Zeek is a documented future extension |
| D-5 | Primary demo corpus is **committed synthetic EVE**, not a downloaded dataset |
| D-6 | AI briefs are narrative-only and can never mutate detection state |
| D-7 | Events keep promoted typed columns **plus** a validated JSONB payload |
| D-8 | Auth/audit/rate-limit primitives exist from M1; M6 completes and proves them |
| D-9 | **Isolated Suricata Docker lab (`infra/lab/`) deferred to M2.** M1 is file-and-API driven only: no packet capture, no traffic generation, no live-traffic component. Rationale: sensor config, capture permissions, and topology introduce reproducibility risk that would compromise the M1 gates. |
| D-10 | Scheduler and periodiq deferred to M2 (ADR-010); the M1 worker registers one actor, `import_dataset` (Chunk 4, ADR-014) |

## Defects found and fixed in Chunk 1 review (2026-08-30)

| Defect | Effect | Fix |
|---|---|---|
| `RedisBroker(url=..., password=...)` ignored the password | Worker would fail with `NOAUTH` on first Redis command | Explicit authenticated `redis.Redis` client; regression test |
| Worker liveness probe `pgrep -f 'dramatiq …'` matched its own `sh -c` wrapper | Healthcheck always passed | `[d]ramatiq` pattern; policy test |
| `cap_drop: ALL` on the official `postgres`/`redis` images | Both restart-looped (`setresuid failed`); the stack had never started | `user: postgres` / `user: redis`; policy test |
| No `.gitattributes`; CRLF checkout on Windows | Bind-mounted `01_roles.sh` unusable inside the container | LF normalisation for all text files |
| README / STATUS / CHANGELOG described tests and a frontend that did not exist | Misleading status | This revision |

## Open risks being carried

| Risk | Current handling |
|---|---|
| Detector thresholds may need substantial tuning; accuracy is unknown | M2 fixtures + `docs/evaluation.md` measure it honestly before any claim is made |
| Beaconing false positives from legitimate periodic traffic (NTP, updates) | Known-periodic destination allow-list planned in D-004 |
| Indirect prompt injection via log content | Contained, not eliminated — see `THREAT_MODEL.md` R-3 |
| Metadata egress to Perplexity is non-zero even when redacted | Opt-in per incident, off by default, offline mode supported — R-2 |
| Public-dataset licence obligations | Provenance + required citation stored per ingest batch |
| `/api/v1/meta/version` is unauthenticated | No auth layer exists yet; git SHA already withheld in production; permission-gated in Chunk 6 |
| A `db_data` volume initialised before Chunk 2 lacks the migrator's `CREATE ON DATABASE` grant (init scripts run once) | `make down && make up` re-initialises it; recorded in ADR-012 |
| Base images and GitHub Actions pinned by tag, not digest | Decision F-5; `make pin-digests` prints the digests. `astral-sh/setup-uv` publishes no major tags from v8 on and is already pinned to an exact release |

## Next actions

1. Both workflows are green on the Node 24 action releases with no annotations, and the `ci` backend job saves its uv cache (E-16). The SonarCloud check, an external app rather than a workflow here, still fails its quality gate and the finding is visible only on the private dashboard (E-17): confirm the outcome of the sink-side neutralisation on the push carrying it; if the gate still fails, read the finding there or remove the app from the repository.
2. Chunk 4 is confirmed in CI (E-28); nothing is outstanding for it.
3. Chunk 5: asset inventory — service, CIDR resolution with most-specific-match, bulk seed (`make seed`) — and the event read queries with keyset pagination. Their HTTP routes land together with authentication in Chunk 6 (ADR-014).
4. Keep this file and `THREAT_MODEL.md` updated per chunk, not afterwards.
