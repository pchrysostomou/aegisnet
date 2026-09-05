# AegisNet — Network Threat Detection Lab

A self-hosted, **defensive-only** platform for ingesting network security telemetry,
detecting suspicious behaviour with deterministic heuristics, correlating findings into
incidents, and generating evidence-based AI investigation briefs for human analysts.

> **Status: Milestone 1, Chunk 5 — asset inventory and event reads.**
> The five-service stack builds and reaches healthy from a clean clone, `make migrate`
> creates the schema with least-privilege grants, `make seed` loads the lab inventory,
> `make demo-ingest` stores the committed synthetic corpus idempotently, and the CLI
> resolves addresses to assets and queries events with bounded keyset pagination. There
> is **no HTTP API beyond health and version, no detection, no authentication and no
> analyst UI yet**; the routes arrive with authentication in Chunk 6.
> [`docs/STATUS.md`](docs/STATUS.md) is the authoritative record of what exists and what
> has been verified.

---

## Safety and scope boundary

AegisNet is a defensive, read-only analysis tool. These boundaries are structural, not
aspirational:

- **No offensive capability.** It does not scan, probe, exploit, enumerate, brute-force, or
  target any system. It contains no such tooling and never will.
- **No automated response.** It never blocks traffic, changes a firewall, disables an
  account, quarantines a host, or takes any other real-world action. The AI layer may only
  *recommend* safe actions for a human to review and perform manually.
- **Local-only by default.** Every published port binds to `127.0.0.1`. The database and
  Redis publish no host ports at all.
- **Analyse only what you are authorised to analyse.** Use the project's own synthetic
  corpus, your own lab traffic, or telemetry from systems you administer.
- **Milestone 1 never touches a network interface.** There is no packet capture and no
  traffic generation; the isolated Suricata lab is deferred to Milestone 2
  ([ADR-009](docs/adr/ADR-009-defer-suricata-lab.md)).
- **Captures and live sensor output are never committed.** `.gitignore` treats `*.pcap`,
  `*.pcapng`, and `eve*.json` as sensitive data rather than fixtures.

---

## What exists right now

| Area | State |
|---|---|
| Milestone 0 planning package (PRD, architecture, threat model, data model, API contract, delivery plan, evaluation plan) | Complete |
| Repository scaffolding: ignore rules, LF normalisation, licence, changelog, environment template, secret bootstrap, pre-commit config | Complete |
| Docker Compose topology and container images (five services, hardened, loopback-only) | **Built and started locally; all five services report healthy** |
| Backend application (FastAPI, settings, JSON logging, error envelope, `/healthz`, `/readyz`, `/api/v1/meta/version`) | Complete for Chunk 1 |
| Dramatiq worker | Boots, authenticates to Redis, registers one actor, `import_dataset` ([ADR-014](docs/adr/ADR-014-ingest-entrypoints-ports-and-worker-layer.md)); the scheduler stays deferred ([ADR-010](docs/adr/ADR-010-defer-scheduler.md)) |
| Frontend | Health placeholder only: one page and `GET /api/health` |
| Schema: Alembic baseline for the nine M1 tables (`users`, `service_tokens`, `refresh_tokens`, `audit_log`, `ingest_batches`, `events`, `ingest_rejects`, `assets`, `asset_networks`), ORM models, enum types, indexes incl. `UNIQUE (event_hash)` and `GIST (cidr inet_ops)`, least-privilege grants | Complete for Chunk 2; `make migrate` applies it, `make test-db` proves it ([ADR-012](docs/adr/ADR-012-migrations-in-package-and-role-grants.md)) |
| EVE domain (`backend/src/aegisnet/domain/eve/`): parse limits, sanitiser, Pydantic schema, canonical `event_hash`, normaliser to `NormalizedEvent` or `Reject` | Complete for Chunk 3; pure and clock-free ([ADR-013](docs/adr/ADR-013-event-hash-payload-and-event-type-triage.md)) |
| Dataset registry with id-only, symlink-free, checksum-verified resolution; seeded synthetic generator and the committed benign corpus (2000 events) | Complete for Chunk 3 ([`samples/README.md`](samples/README.md)) |
| Ingest service: streaming NDJSON, per-line rejects with reason codes, idempotent storage by `event_hash`, batch provenance and counts; operator CLI and `make demo-ingest` | Complete for Chunk 4 ([ADR-014](docs/adr/ADR-014-ingest-entrypoints-ports-and-worker-layer.md)); HTTP routes arrive with authentication in Chunk 6 |
| Asset inventory: validated specs, cross-asset overlap refusal, most-specific CIDR resolution, upsert seeding (`make seed`), filtered keyset-paginated lists; event reads with bounded windows, cursors, filters incl. by asset, and stats | Complete for Chunk 5 ([ADR-015](docs/adr/ADR-015-asset-inventory-and-event-reads.md)); HTTP routes arrive with authentication in Chunk 6 |
| Tests | Hermetic suite (unit, integration, security), no database or Redis needed; plus an opt-in database suite (`make test-db`) that migrates, compares the ORM with the schema, and asserts the runtime role's privileges against an ephemeral PostgreSQL 16 |
| CI and security workflows | Both green: `ci` including the stack gate on the runner, and `security` after the dependency upgrades its first run demanded. Every action now runs on the Node 24 runtime — see `docs/STATUS.md` |
| HTTP routes for ingest, assets and events, auth/RBAC/audit/rate limiting, detection, correlation, AI briefs, dashboard | Not started — Chunk 6 and later milestones |

---

## Technology

Python 3.12 · FastAPI · SQLAlchemy · Alembic · Pydantic · PostgreSQL 16 · Redis 7 ·
Dramatiq · Next.js 15 · TypeScript · Docker Compose · Suricata EVE JSON · pytest · Ruff ·
mypy · GitHub Actions. Rationale is in [`ARCHITECTURE.md`](ARCHITECTURE.md). Tailwind is
planned but not yet in the tree.

---

## Quickstart

Requirements: Docker with Compose v2, Python 3 on the host (for the bootstrap script),
`make`. For native backend development also [`uv`](https://docs.astral.sh/uv/); for the
frontend Node 22 with `corepack`.

```bash
git clone git@github.com:pchrysostomou/aegisnet.git
cd aegisnet

# 1. Generate a local .env containing random, development-only secrets.
#    Idempotent: never overwrites an existing .env without --force, never prints a secret.
make bootstrap

# 2. Build the images, start the stack, and wait until every service is healthy.
make up

# 3. Create the schema. Runs `alembic upgrade head` inside the api image as the migrator
#    role; the runtime role never holds DDL rights.
make migrate
make migrate-status                             # revision held by the database vs. the head this build expects

# 4. Seed the lab inventory (14 hosts, idempotent by hostname), then ingest the registered
#    synthetic corpus (2000 events). Run the ingest twice: the second run stores nothing
#    and reports every line as a duplicate (FR-1.4).
make seed
make demo-ingest
make demo-ingest LABEL=second-run
make demo-ingest MODE=async LABEL=via-worker     # enqueues for the worker; prints the batch id
make batch ID=<uuid>                            # poll it

# Explore through the operator CLI (JSON out; the HTTP routes arrive with auth in Chunk 6).
docker compose run --rm api python -m aegisnet.cli resolve 10.10.0.53
docker compose run --rm api python -m aegisnet.cli assets -q resolver
docker compose run --rm api python -m aegisnet.cli events --from 2026-09-01T00:00:00Z \
    --to 2026-09-02T00:00:00Z --type dns --limit 5
docker compose run --rm api python -m aegisnet.cli event-stats --from 2026-09-01T00:00:00Z \
    --to 2026-09-02T00:00:00Z

# 5. Probe it. Everything is bound to 127.0.0.1.
curl http://127.0.0.1:8000/healthz              # {"status":"ok"}
curl http://127.0.0.1:8000/readyz               # {"status":"ok"} once PostgreSQL and Redis answer
curl http://127.0.0.1:8000/api/v1/meta/version  # includes "schema_revision":"0002_asset_network_delete_grant"
curl http://127.0.0.1:3000/api/health           # {"status":"ok"}
open http://127.0.0.1:8000/docs                 # OpenAPI UI (disabled when ENV=production)

# 6. Tear down, including the database volume.
make down
```

`make help` lists every target. Targets are added by the commit that introduces the thing
they operate on, so the Makefile never advertises a command that cannot work.

### Checks

```bash
make backend-install   # uv sync --frozen
make check             # verify-ignore + ruff (backend, tools) + import contracts + format + mypy + pytest
make test-cov          # the suite with a coverage report
make compose-test      # the same suite inside the hermetic test-runner container
make compose-config    # parse and interpolate both Compose manifests without starting anything
make test-db           # the database suite against an ephemeral PostgreSQL 16 (needs .env)
```

The default suite is hermetic: readiness probes are replaced with in-process fakes, and the
security tests read the committed Compose files, Dockerfiles, `.env.example`, `.gitignore`
and pre-commit configuration **as data**. They prove what the manifests declare. Whether a
running stack honours those declarations is proven separately by `make up`, which the CI
`stack` job also runs.

The database suite (`backend/tests/db/`, marker `db`) is opt-in and runs against a
throwaway PostgreSQL 16 started from `docker-compose.test.yml` with `--profile db`: it
applies the baseline, runs Alembic's own `compare_metadata` to prove the ORM and the
migrated schema agree, asserts the runtime role's exact privilege matrix (T-5.3), and
downgrades to base to prove nothing is left behind. CI runs it as the `migrations` job.

### Container topology

Five services: `db` (PostgreSQL 16), `redis` (Redis 7), `api` (FastAPI), `worker`
(Dramatiq, one actor: `import_dataset`), `web` (Next.js placeholder). `db`, `redis` and
`worker` publish no host port. `api` and `worker` mount `./samples` read-only at
`/app/samples`, the only place a dataset can be imported from. `api` and `web` publish only on `127.0.0.1`, so nothing is
reachable from another host. Every service sets `cap_drop: ["ALL"]` and
`no-new-privileges:true`.

Every container runs as a non-root user. The project images set `USER` in their
Dockerfiles. The official `postgres` and `redis` images start as root and drop privileges
with `gosu`/`setpriv`, which needs `CAP_SETUID` and therefore fails under `cap_drop: ALL`;
they are started directly as `postgres` and `redis` via `user:` so no privilege switch is
ever attempted. `read_only` root filesystems and image digest pinning are tracked as later
work (Milestone 6 and decision F-5) and are **not** applied.

The worker's healthcheck is process liveness only and makes no readiness claim. Readiness
(`/readyz`) covers PostgreSQL and Redis reachability and nothing else; it names no
component in its response.

The database is initialised with two least-privilege roles by
[`infra/postgres/init/01_roles.sh`](infra/postgres/init/01_roles.sh): `aegisnet_migrator`
owns the schema, `aegisnet_app` is the runtime role and never receives DDL rights. The script
validates every interpolated role name and secret against a strict allowlist and fails closed,
and it creates no tables. The schema is created only by `make migrate`, which runs the
Alembic revisions shipped inside the package under the migrator role; the revision itself
grants the runtime role `SELECT, INSERT, UPDATE` on the ordinary tables and `SELECT, INSERT`
on `audit_log` — never `UPDATE` or `DELETE` there, and no `DELETE` anywhere
([ADR-012](docs/adr/ADR-012-migrations-in-package-and-role-grants.md)).

### Secrets

`.env` is gitignored and additionally blocked by a pre-commit hook. `make bootstrap` replaces
every `__REPLACE_ME__` placeholder in [`.env.example`](.env.example) with
`secrets.token_urlsafe(48)` and writes the file with `0600` permissions where the platform
supports it. The application refuses to start while any secret still holds a placeholder,
unless `ENV=test`. These are **development-only** credentials for a local lab; production
secret management is out of scope. See
[ADR-011](docs/adr/ADR-011-bootstrap-env-secrets.md).

### Line endings

`.gitattributes` normalises every text file to LF on every platform. Several files are
mounted or copied straight into Linux containers — the PostgreSQL init script in
particular — and a CRLF checkout (the Git for Windows default) breaks them.

---

## Licence

[MIT](LICENSE). Chosen deliberately rather than accepted from a repository template: the
project is a portfolio and learning artefact, and a permissive licence keeps it maximally
reusable. The licence covers this project's own code only — it does not extend to any public
dataset an operator chooses to fetch, and those carry their own citation and use obligations
recorded per ingest batch.

---

## Documentation

| Document | Contents |
|---|---|
| [`PLANNING.md`](PLANNING.md) | Index of the Milestone 0 planning package |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | Components, data flow, technology rationale |
| [`THREAT_MODEL.md`](THREAT_MODEL.md) | Threats, mitigations, residual risks |
| [`docs/STATUS.md`](docs/STATUS.md) | What is built, what is not, what has been verified |
| [`docs/PRD.md`](docs/PRD.md) | Product requirements |
| [`docs/data-model.md`](docs/data-model.md) | PostgreSQL schema design |
| [`docs/api-milestone-1.md`](docs/api-milestone-1.md) | Milestone 1 API contract |
| [`docs/delivery-plan.md`](docs/delivery-plan.md) | Six-milestone plan |
| [`docs/evaluation.md`](docs/evaluation.md) | Detection evaluation methodology (results intentionally empty) |
| [`docs/adr/`](docs/adr) | Architecture decision records |
| [`backend/README.md`](backend/README.md) | What the backend package contains today |
| [`frontend/README.md`](frontend/README.md) | The web placeholder |
| [`samples/README.md`](samples/README.md) | Datasets, the registry, how a file gets imported |
| [`CHANGELOG.md`](CHANGELOG.md) | Notable changes |

`SECURITY.md` is added in the commit that introduces the first security controls it would
describe (authentication and RBAC, Chunk 6).
