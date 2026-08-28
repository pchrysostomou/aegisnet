# AegisNet — Network Threat Detection Lab

A self-hosted, **defensive-only** platform for ingesting network security telemetry,
detecting suspicious behaviour with deterministic heuristics, correlating findings into
incidents, and generating evidence-based AI investigation briefs for human analysts.

> **Status: Milestone 1, Chunk 1 — repository scaffolding.**
> There is **no application code in this repository yet**: no API, no database, no
> ingestion, no detection, no UI. Milestone 0 planning is complete and is published here.
> [`docs/STATUS.md`](docs/STATUS.md) is the authoritative record of what exists and what has
> been verified.

---

## Safety and scope boundary

AegisNet is a defensive, read-only analysis tool. These boundaries are structural, not
aspirational:

- **No offensive capability.** It does not scan, probe, exploit, enumerate, brute-force, or
  target any system. It contains no such tooling and never will.
- **No automated response.** It never blocks traffic, changes a firewall, disables an
  account, quarantines a host, or takes any other real-world action. The AI layer may only
  *recommend* safe actions for a human to review and perform manually.
- **Local-only by default.** Every published port will bind to `127.0.0.1`. The database and
  Redis will publish no host ports at all.
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
| Repository scaffolding: ignore rules, licence, changelog, environment template, secret bootstrap, pre-commit config | This commit |
| Docker Compose topology | Not yet committed |
| Backend application (FastAPI, config, logging, health endpoints) | Not yet committed |
| Frontend health placeholder | Not yet committed |
| Tests | Not yet committed |
| CI and security workflows | Not yet committed |
| Migrations, ORM models, EVE ingestion, detection, correlation, auth/RBAC/audit/rate limiting, AI briefs, dashboard | Not started — Chunk 2 onward and later milestones |

---

## Planned technology

Python 3.12 · FastAPI · SQLAlchemy · Alembic · Pydantic · PostgreSQL 16 · Redis 7 ·
Dramatiq · Next.js 14 · TypeScript · Tailwind · Docker Compose · Suricata EVE JSON ·
pytest · Ruff · mypy · GitHub Actions. Rationale is in
[`ARCHITECTURE.md`](ARCHITECTURE.md).

---

## Local setup so far

Only environment bootstrap exists at this commit. There is nothing to build or run yet.

```bash
git clone git@github.com:pchrysostomou/aegisnet.git
cd aegisnet

# Generate a local .env containing random, development-only secrets.
# Idempotent: it never overwrites an existing .env without --force, and never prints a secret.
make bootstrap
```

`make help` lists the currently implemented targets. Build, run, test, lint, and CI targets
are added in the commits that introduce the things they operate on, so the Makefile never
advertises a command that cannot work.

### Secrets

`.env` is gitignored and additionally blocked by a pre-commit hook. `make bootstrap` replaces
every `__REPLACE_ME__` placeholder in [`.env.example`](.env.example) with
`secrets.token_urlsafe(48)` and writes the file with `0600` permissions where the platform
supports it. These are **development-only** credentials for a local lab; production secret
management is out of scope. See [ADR-011](docs/adr/ADR-011-bootstrap-env-secrets.md).

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
| [`CHANGELOG.md`](CHANGELOG.md) | Notable changes |

`SECURITY.md` is added in the commit that introduces the first security controls it would
describe.
