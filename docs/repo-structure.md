# AegisNet — Monorepo Structure

Status: **Planned layout. Directories are created milestone by milestone, not all at once.**
Last updated: 2026-08-28

```
aegisnet/
├── README.md                     # quickstart, demo script, screenshots
├── ARCHITECTURE.md
├── THREAT_MODEL.md
├── SECURITY.md                   # policy, RBAC matrix, secret handling, disclosure
├── LICENSE
├── CHANGELOG.md
├── .env.example                  # every variable, no real values
├── .gitignore
├── .dockerignore
├── .pre-commit-config.yaml       # ruff, ruff-format, secret scan, PII canary scan
├── Makefile                      # up, down, seed, test, lint, typecheck, migrate, demo
├── docker-compose.yml            # db, redis, api, worker, scheduler, web
├── docker-compose.override.yml.example
│
├── docs/
│   ├── STATUS.md                 # living milestone status (source of truth for progress)
│   ├── PRD.md
│   ├── repo-structure.md
│   ├── data-model.md
│   ├── api-milestone-1.md
│   ├── delivery-plan.md
│   ├── detection-rules.md        # D-001..D-005 specs, params, tuning notes
│   ├── evaluation.md             # method + labelled results per detector
│   ├── perplexity-integration.md # packet schema, redaction, prompts, failure modes
│   ├── RELEASE_CHECKLIST.md
│   ├── demo-script.md
│   ├── adr/                      # ADR-001.md ... one file per decision
│   └── screenshots/
│
├── backend/
│   ├── pyproject.toml            # ruff, mypy, pytest config
│   ├── uv.lock                   # pinned deps
│   ├── Dockerfile                # multi-stage, non-root
│   ├── alembic.ini               # no URL; points into the package (ADR-012)
│   ├── src/aegisnet/
│   │   ├── main.py               # FastAPI app factory
│   │   ├── config.py             # pydantic-settings, SecretStr for all secrets
│   │   ├── logging.py            # structured JSON logs, secret scrubbing filter
│   │   │
│   │   ├── api/
│   │   │   ├── deps.py           # auth, RBAC, pagination, rate-limit dependencies
│   │   │   ├── errors.py         # global handlers, correlation ids
│   │   │   ├── schemas/          # request/response Pydantic DTOs
│   │   │   └── v1/
│   │   │       ├── health.py  auth.py  ingest.py  assets.py
│   │   │       ├── events.py  alerts.py  incidents.py
│   │   │       ├── briefs.py  reports.py  audit.py
│   │   │
│   │   ├── domain/               # PURE. no I/O, no ORM, no network.
│   │   │   ├── ports.py          # Protocols the services call and adapters implement (ADR-014)
│   │   │   ├── models.py         # frozen dataclasses: NormalizedEvent, EventWindow, DetectionResult
│   │   │   ├── eve/              # EVE parsing + validation (schema.py, normalizer.py, sanitize.py)
│   │   │   ├── detectors/        # base.py, port_scan.py, auth_failure.py,
│   │   │   │                     # dns_anomaly.py, beaconing.py, volume_anomaly.py, registry.py
│   │   │   ├── severity.py       # severity/confidence scoring, auditable formula
│   │   │   ├── correlation.py    # entity+time windowed grouping, timeline assembly
│   │   │   ├── redaction/        # pseudonymizer.py, denylist.py, packet_builder.py
│   │   │   └── reporting/        # markdown renderer (deterministic, no I/O)
│   │   │
│   │   ├── services/             # use-cases; orchestrate domain + adapters
│   │   │   ├── ingest_service.py  detection_service.py  correlation_service.py
│   │   │   ├── baseline_service.py brief_service.py  export_service.py
│   │   │   ├── auth_service.py    audit_service.py
│   │   │
│   │   ├── adapters/
│   │   │   ├── db/               # engine, session, ORM models, ingest/asset/event stores (port impls),
│   │   │   │                     # migrations/ (Alembic env + versions, in-package: ADR-012)
│   │   │   ├── queue/            # dramatiq broker factory, queue/actor names, enqueuers
│   │   │   │                     # (actors themselves live in workers/: ADR-014)
│   │   │   ├── cache/            # redis client, rate limiter, response cache
│   │   │   ├── perplexity/       # client.py, prompts/, response_schema.py, citations.py
│   │   │   └── files/            # dataset registry + safe path resolution
│   │   │
│   │   ├── workers/              # entrypoint layer: main.py (dramatiq entrypoint), actors.py
│   │   └── cli.py                # argparse (ADR-014): datasets, import-dataset, batch, ...
│   │
│   └── tests/
│       ├── conftest.py           # testcontainers/ephemeral pg, StubBroker, factories
│       ├── unit/
│       │   ├── eve/  detectors/  correlation/  redaction/  severity/  reporting/
│       ├── integration/
│       │   ├── test_ingest_api.py  test_detection_pipeline.py
│       │   ├── test_correlation.py test_rbac_matrix.py
│       │   ├── test_brief_flow.py  test_audit_log.py
│       ├── security/
│       │   ├── test_redaction_canaries.py    # no forbidden data can reach Perplexity
│       │   ├── test_prompt_injection.py      # briefs cannot mutate detection state
│       │   ├── test_path_traversal.py  test_payload_limits.py
│       └── fixtures/
│           ├── eve/              # hand-built EVE JSON lines
│           └── labelled/         # per-detector positive/ and negative/ cases + labels.yml
│
├── frontend/
│   ├── package.json  pnpm-lock.yaml  tsconfig.json  tailwind.config.ts
│   ├── Dockerfile                # multi-stage, non-root
│   ├── src/
│   │   ├── app/
│   │   │   ├── layout.tsx  page.tsx
│   │   │   ├── login/            incidents/            incidents/[id]/
│   │   │   ├── assets/           audit/
│   │   ├── components/
│   │   │   ├── IncidentTable.tsx  SeverityBadge.tsx  Timeline.tsx
│   │   │   ├── EvidenceTable.tsx  AlertCard.tsx  StatusControl.tsx
│   │   │   ├── BriefPanel.tsx     CitationList.tsx  UnverifiedTag.tsx
│   │   │   └── SafeMarkdown.tsx   # strict allow-list renderer
│   │   ├── lib/                  # api client, auth, zod schemas mirroring backend DTOs
│   │   └── types/
│   └── tests/                    # vitest unit + playwright smoke
│
├── samples/
│   ├── README.md                 # provenance, licence, required citations per dataset
│   ├── registry.yml              # dataset id → file, checksum, licence, citation
│   ├── synthetic/                # committed, generated EVE JSON (primary demo path)
│   └── external/                 # gitignored; operator-fetched public datasets
│
├── infra/
│   ├── lab/
│   │   ├── docker-compose.lab.yml   # OPT-IN isolated Suricata lab, internal-only network
│   │   ├── suricata/               # suricata.yaml, custom rules
│   │   └── generators/             # benign + scripted-behaviour traffic scripts (lab-only)
│   ├── postgres/init/             # roles, least-privilege grants, audit-table grants
│   └── scripts/                   # wait-for-it, seed.sh, demo.sh
│
├── tools/
│   ├── gen_synthetic_eve.py       # deterministic, seeded EVE generator
│   └── eval_report.py             # builds docs/evaluation.md metrics tables
│
└── .github/workflows/
    ├── ci.yml                     # ruff, mypy, pytest (unit+integration+security), coverage gate
    ├── frontend.yml               # tsc, eslint, vitest, build
    └── security.yml               # pip-audit, npm audit, secret scan, docker image scan
```

## Conventions

- **Import discipline:** `domain/` may not import from `adapters/`, `services/`, or `api/`. Enforced in CI with
  an import-linter contract. This is what keeps detectors pure and testable.
- **Naming:** detector modules match their rule id (`D-001` → `port_scan.py`), and `docs/detection-rules.md` is
  the single source of truth for ids, versions, and default parameters.
- **Migrations:** every schema change ships an Alembic revision in the same PR; no auto-create in any environment.
- **Fixtures:** every labelled fixture directory contains a `labels.yml` stating expected detections, so the
  evaluation harness never hardcodes expectations in test bodies.
- **Nothing real in `samples/synthetic/`:** all IPs from RFC 5737/RFC 1918 documentation ranges, all domains from
  `example.com`/`example.test`.
