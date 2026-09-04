# AegisNet — Project Status

**Last updated:** 2026-08-30 · **Current phase:** M1 Chunk 1 (foundation) verified locally; CI not yet run · **Version:** none tagged

> This file is the single source of truth for progress. It states only what has **evidence**. Nothing below is
> claimed to run, pass, or exist unless an evidence entry is given.

---

## Current state

| | |
|---|---|
| Phase | **M1 — Chunk 1 (foundation) complete locally; Chunk 2 (migrations) not started** |
| Application code written | Settings, JSON logging, error envelope, `/healthz`, `/readyz`, `/api/v1/meta/version`, DB/Redis connectivity adapters, Dramatiq broker with zero actors |
| Frontend | Health placeholder: one page, `GET /api/health` |
| Tests written | 124 (unit, integration, security), all hermetic |
| Tests run | **Yes, locally** — see evidence E-1, E-2 |
| Docker stack | **Built and started locally; all five services healthy** — see evidence E-3 |
| Database | Roles `aegisnet_migrator` / `aegisnet_app` created at init; **no migrations, no tables** |
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
| E-17 | SonarCloud Code Analysis check (`sonarqubecloud` app) on 9ef3024, 89f8dae, a8e9510, e712429, fc53775 | ❌ every one "Quality Gate failed"; the only failing condition is **Security Rating on New Code C** (required A). The project is private on sonarcloud.io, the check carries no annotation and no notification e-mail exists, so the exact finding could not be read. The two request-derived flows Sonar's Python taint rules cover are now neutralised at the sink (`untrusted_text` in the unhandled-exception log call; `canonical_correlation_id` before the response header); 135 tests, 96% coverage. Result recorded on the push carrying it |

## Milestone tracker

| Milestone | Status | Evidence | Notes |
|---|---|---|---|
| M0 Planning | ✅ Complete | This doc set | PRD, architecture, threat model, data model, M1 API, delivery plan, evaluation plan |
| M1 Foundation / ingest / normalize / assets | 🟡 In progress — Chunk 1 done | E-1 – E-8 | Next: Chunk 2 Alembic baseline |
| M2 Five detectors + labelled fixtures | ⬜ Not started | — | Blocked on M1 |
| M3 Correlation / incidents / workflow | ⬜ Not started | — | Blocked on M2 |
| M4 Analyst dashboard | ⬜ Not started | — | Blocked on M3 |
| M5 Perplexity brief + Markdown export | ⬜ Not started | — | Blocked on M4 (safe renderer first) |
| M6 Hardening / evaluation / release | ⬜ Not started | — | Gate for `v1.0.0` |

## Milestone 1 chunk tracker

| Chunk | Contents | Status |
|---|---|---|
| 1 | Skeleton, Compose, config, logging, health, worker topology, web placeholder, tests, CI | ✅ Locally verified |
| 2 | Alembic baseline migration, ORM models, DB grants incl. `audit_log` | ⬜ |
| 3 | EVE domain: schema, sanitizer, normalizer, `event_hash`, synthetic generator, registry | ⬜ |
| 4 | Ingest service, first Dramatiq actor, rejects, idempotency | ⬜ |
| 5 | Assets API, events read API | ⬜ |
| 6 | Auth, RBAC, audit, rate limits, `SECURITY.md` | ⬜ |
| 7 | Docs update at the M1 gate with CI evidence | ⬜ |

## Definition-of-Done checklist (v1.0.0)

- [ ] `docker compose up --build` starts the full local environment — *Chunk 1 topology does (E-3); the full environment does not exist yet*
- [ ] Documented safe sample dataset ingests via one command
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
| D-10 | Scheduler and periodiq deferred to M2 (ADR-010); the M1 worker registers zero actors |

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
| Base images and GitHub Actions pinned by tag, not digest | Decision F-5; `make pin-digests` prints the digests. `astral-sh/setup-uv` publishes no major tags from v8 on and is already pinned to an exact release |

## Next actions

1. Both workflows are green on the Node 24 action releases with no annotations, and the `ci` backend job saves its uv cache (E-16). The SonarCloud check, an external app rather than a workflow here, still fails its quality gate and the finding is visible only on the private dashboard (E-17): confirm the outcome of the sink-side neutralisation on the push carrying it; if the gate still fails, read the finding there or remove the app from the repository.
2. Chunk 2: Alembic baseline migration for the nine M1 tables, ORM models, `audit_log` grants, `SCHEMA_REVISION` wired to the Alembic head, `db-test` service in `docker-compose.test.yml`.
3. Keep this file and `THREAT_MODEL.md` updated per chunk, not afterwards.
