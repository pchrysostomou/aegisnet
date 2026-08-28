# Milestone 1 implementation prompt

Paste this as the next instruction to begin implementation. It is scoped to M1 only.

---

You are the implementation lead for AegisNet. The planning phase is complete and locked in `docs/PRD.md`,
`ARCHITECTURE.md`, `THREAT_MODEL.md`, `docs/data-model.md`, `docs/api-milestone-1.md`,
`docs/repo-structure.md`, `docs/evaluation.md`, and `docs/STATUS.md`. Read them and do not contradict them; if
you believe a planning decision is wrong, say so and stop rather than silently diverging.

**Implement Milestone 1 only.** Do not implement detectors, correlation, incidents, the dashboard, the Perplexity
integration, or Markdown export. Their absence is the milestone boundary.

## Scope

1. **Repo skeleton** exactly as `docs/repo-structure.md` describes, limited to the directories M1 needs.
2. **Docker Compose**: `db` (PostgreSQL 16), `redis` (7), `api`, `worker`, `scheduler`, plus a `web` placeholder
   that builds and serves a health page. Healthchecks on every service; published ports bound to `127.0.0.1`;
   non-root users; pinned base image digests.
3. **Config & logging**: `pydantic-settings` with `SecretStr` for all secrets; `.env.example` listing every
   variable with safe placeholder values; structured JSON logging with a filter that scrubs secrets and never
   interpolates untrusted log content into message strings.
4. **Alembic baseline migration** creating: `ingest_batches`, `events`, `ingest_rejects`, `assets`,
   `asset_networks`, `users`, `service_tokens`, `refresh_tokens`, `audit_log` — with the columns, enums,
   constraints, and indexes specified in `docs/data-model.md`, including the `UNIQUE (event_hash)` and the
   `GIST (cidr inet_ops)` index. Also create the least-privilege Postgres roles and grant `INSERT`/`SELECT` only
   on `audit_log` to the app role.
5. **EVE pipeline** in `domain/eve/`: Pydantic schema for the common fields and the `alert`/`dns`/`http`/`flow`/
   `tls`/`fileinfo`/`anomaly` sub-objects, a sanitizer that strips C0/C1 control characters and caps string
   lengths, a normalizer producing `NormalizedEvent`, and the canonical `event_hash`. Pure — no I/O, no ORM.
6. **Ingest service**: streaming line-by-line NDJSON parse, pre-parse size/line/depth/key-count limits,
   per-line rejects into `ingest_rejects`, idempotency via `event_hash`, batch bookkeeping, and a Dramatiq actor
   for async normalization with a `sync` path for tests.
7. **Dataset registry**: `samples/registry.yml` with id, relative path, sha256, licence, and required citation;
   safe resolution that `realpath`s and asserts containment inside `samples/`, rejects symlinks, and accepts no
   client-supplied path.
8. **Synthetic EVE generator** `tools/gen_synthetic_eve.py`: seeded and deterministic, emits a manifest of
   expected event counts by type, uses only RFC 5737/RFC 1918 addresses and `example.test` domains. Commit at
   least one benign corpus and register it.
9. **Asset inventory**: CRUD, bulk seed, and `GET /assets/resolve` with most-specific-CIDR-wins resolution and
   overlap rejection.
10. **Event read API**: keyset pagination on `(event_time, id)`, the filters listed in `docs/api-milestone-1.md`,
    and payload visibility restricted to `analyst`+.
11. **Auth & guardrails**: Argon2id password hashing, login with generic failure messages, short-lived JWT access
    tokens, rotating refresh tokens with reuse detection, service tokens for ingest, a per-route permission
    dependency with **no implicit-allow path**, Redis-backed rate limits per the spec table, audit-log writes for
    every auth event / ingest / asset mutation / RBAC denial, and a global exception handler returning the
    documented error shape with a correlation id and no stack traces.
12. **Tests**: unit tests for EVE parsing, sanitization, hashing, and CIDR resolution; integration tests for
    ingest idempotency, partial-failure tolerance, and the RBAC route-enumeration check; security tests for path
    traversal, oversized body, oversized line, deep JSON, control-character/ANSI log injection, and error-shape
    leakage. Use an ephemeral PostgreSQL and Dramatiq's `StubBroker` so tests are deterministic.
13. **CI** `.github/workflows/ci.yml`: ruff, ruff-format check, mypy strict on `domain/`, pytest (unit +
    integration + security) with a coverage gate, and a secret scan. Plus `security.yml` running `pip-audit`.
14. **Docs**: write `README.md` (quickstart, exact demo commands, what M1 does and does not do) and
    `SECURITY.md` (RBAC permission matrix, secret handling, reporting policy). Update `docs/STATUS.md` with real
    evidence.

## Before writing any code, output

1. The M1 goal restated in two sentences.
2. Acceptance criteria as a checklist (start from `docs/delivery-plan.md` M1 and `docs/api-milestone-1.md`).
3. The complete list of files you will create, with a one-line purpose each.
4. Any architecture decision you are making that the planning docs did not already fix, with rationale.
5. The security risks this milestone touches, referencing `THREAT_MODEL.md` ids, and how each is handled.
6. The test list: what is unit, what is integration, what is a security test.
7. The exact commands a reviewer runs to verify the milestone.

Then wait for approval before generating code.

## Rules for the implementation

- Deliver in reviewable chunks, ordered: skeleton + compose + config → migrations → EVE domain + tests →
  ingest service + tests → assets + events API → auth/RBAC/audit/rate limits → CI → docs. Stop between chunks.
- Never claim code ran, tests passed, or CI is green without pasting the actual command output. If you cannot
  run something, say "not run" explicitly.
- No secrets in code, compose defaults, or fixtures. `.env.example` only.
- Every inbound API body is a Pydantic model with `extra="forbid"`.
- Treat all log content as untrusted: no string interpolation into logs, no shell, no raw SQL.
- No offensive capability, no scanning, no automated response actions — including in test helpers and lab
  generator scripts.
- `domain/` must not import from `adapters/`, `services/`, or `api/`; add the import-linter contract in this
  milestone so the rule is enforced from day one.
- Update `docs/STATUS.md` and `THREAT_MODEL.md` as part of the milestone, not afterwards.

## Milestone 1 is done when

`docker compose up --build` reaches healthy from a clean clone, `make migrate && make seed && make demo-ingest`
stores the synthetic corpus with counts matching the generator manifest, a second identical ingest adds zero
events, all listed tests pass in GitHub Actions, no route lacks a permission dependency, and `README.md`,
`SECURITY.md`, and `docs/STATUS.md` reflect reality with evidence.
