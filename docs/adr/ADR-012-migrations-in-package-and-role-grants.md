# ADR-012 — Migrations ship inside the package; grants are part of the schema

- Status: accepted
- Date: 2026-09-04
- Milestone: 1, Chunk 2

## Context

`docs/repo-structure.md` places `alembic.ini` and `alembic/versions/` at the backend root.
The runtime image (`backend/Dockerfile`, stage `runtime`) deliberately copies only `src/`
and the project metadata, and `make migrate` has to run **inside** that image so the
migration is applied from the same build that will use the schema, under the migrator
role, without a host Python environment. A top-level `alembic/` directory would either be
left out of the image or force the image to carry more of the repository than it needs.

Two further questions had no recorded answer: which role owns the schema and grants what
to whom, and where the enum labels that both the ORM (an adapter) and the future EVE
normaliser (domain code) need should live.

## Decision

1. **The Alembic environment lives in the package**, at
   `src/aegisnet/adapters/db/migrations/` (`env.py`, `script.py.mako`, `versions/`).
   `backend/alembic.ini` points there and is copied into the runtime image, so the same
   `alembic upgrade head` works natively (`uv run alembic ...`) and in the container
   (`make migrate`). `alembic.ini` carries **no URL**: `env.py` builds it from
   `Settings.migration_url`, the migrator credentials.
2. **The migrator owns every object and the migration issues the grants.** The runtime
   role (`aegisnet_app`) receives `SELECT, INSERT, UPDATE` on the ordinary tables,
   `SELECT, INSERT` on `audit_log` plus `USAGE` on its identity sequence, and `SELECT` on
   `alembic_version`. No `DELETE` is granted anywhere and no DDL right exists: assets
   soft-delete, events are append-only, and the retention job that needs `DELETE` arrives
   in a later milestone with its own revision. The role name reaches the revision through
   `config.attributes["app_role"]`, is validated against the identifier grammar and quoted
   by the dialect before it is interpolated into a `GRANT`.
3. **The migrator also receives `CREATE` on the database** (init script), because the
   `citext` type for `users.email` is a *trusted* extension that a non-superuser may
   install only with that privilege. The app role never gets it.
4. **`audit_log` has no foreign keys.** A referential action (`ON DELETE SET NULL`) would
   rewrite audit rows when a user is deleted, which contradicts append-only (T-2.5). Actor
   ids are stored as plain uuids.
5. **Schema enumerations live in `aegisnet.domain.enums`.** `domain/` may not import from
   `adapters/`, and Chunk 3's normaliser needs the same labels, so the enums sit on the
   pure side and the ORM imports them. The baseline revision duplicates the labels on
   purpose, so a revision stays frozen when the Python enums grow.
6. **`schema_revision()` is read from the packaged scripts.** `/api/v1/meta/version`
   reports the head the build expects. Comparing it with what the database holds is
   `make migrate-status`; a readiness check on the difference is deferred until a route
   exists that would be wrong without it.

## Consequences

- Positive: one migration path for host and container; no credential in any ini file;
  the least-privilege claim in `THREAT_MODEL.md` T-5.3 is proven by
  `backend/tests/db/test_grants.py` rather than asserted.
- Positive: `tests/db/test_migrations.py` runs Alembic's `compare_metadata` against the
  migrated database, so the ORM and the revision cannot drift apart silently.
- Negative: the database suite needs a real PostgreSQL. It is opt-in
  (`AEGISNET_DB_TESTS=1`, `make test-db`, CI job `migrations`), so the default suite
  stays hermetic; the migration environment is excluded from the hermetic coverage gate
  because that suite is where it runs.
- Negative: `docs/repo-structure.md` is now out of date on the location of the Alembic
  files; it is a planned layout and records this ADR as the deviation.
- Negative: an existing `db_data` volume initialised before this chunk lacks the
  `CREATE ON DATABASE` grant, because init scripts run only on first initialisation.
  `make down` (which drops the volume) followed by `make up` re-initialises it.
