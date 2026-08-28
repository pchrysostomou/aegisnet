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

### Not yet present
Docker Compose topology, backend application, health and version endpoints, frontend
placeholder, tests, CI and security workflows, database migrations, ORM models, Suricata EVE
schemas and normalisation, ingestion endpoints, dataset registry, background actors, asset
and event APIs, authentication, RBAC, audit logging, rate limiting, detectors, correlation,
Perplexity integration, reports, dashboard.
