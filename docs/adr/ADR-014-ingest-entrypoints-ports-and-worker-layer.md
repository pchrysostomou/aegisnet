# ADR-014 — Ingest entrypoints, ports in the domain, and the worker layer

- Status: accepted
- Date: 2026-09-05
- Milestone: 1, Chunk 4

## Context

Chunk 4 delivers the ingest use-case: streaming NDJSON into `events`, `ingest_rejects`
and `ingest_batches` with idempotency by `event_hash`, plus the first Dramatiq actor. Four
questions had no recorded answer:

1. The API contract lists `POST /api/v1/ingest/eve` and `/import`, but the authentication
   and RBAC dependencies arrive in Chunk 6, and the delivery plan says no milestone ships
   an unauthenticated endpoint. How does an operator ingest anything in the meantime?
2. `docs/repo-structure.md` puts actors under `adapters/queue/actors/`, yet an actor calls
   a *service*, and the layering rule says services sit above adapters.
3. A service depends on a persistence *port* that an adapter implements. If the port is
   defined in `services/`, the adapter imports upward and the same rule breaks.
4. The runtime image contains only `src/`; where do the registered datasets come from
   inside a container?

## Decision

1. **Ingest ships as a CLI in Chunk 4; the HTTP routes ship with auth in Chunk 6.**
   `python -m aegisnet.cli import-dataset <id> --source-label <label>` runs inside the api
   image (`make demo-ingest`) and is the Milestone 1 demo path. The routes will be thin
   wrappers over the same `IngestService`. The CLI uses `argparse` rather than the
   `typer` the layout sketch mentioned: one fewer dependency for three commands.
2. **Entrypoints are a layer of their own.** `aegisnet.api`, `aegisnet.workers` and
   `aegisnet.cli` are siblings at the top of the import-linter layers contract, above
   `services`, `adapters` and `domain`. Actors therefore live in `aegisnet.workers.actors`,
   the worker process entrypoint is `dramatiq aegisnet.workers.main`, and
   `adapters/queue` keeps only the broker factory plus the queue and actor **names**.
   An enqueuer (`adapters/queue/ingest_queue.py`) builds a `dramatiq.Message` by actor
   name, so nothing below the entrypoint layer imports an actor function. This supersedes
   the `adapters/queue/worker.py` entrypoint of ADR-010; that ADR's deferral of the
   scheduler and periodiq stands.
3. **Ports live in the domain.** `aegisnet.domain.ports` holds the `IngestStore`
   Protocol and the value objects it exchanges (`BatchProvenance`, `BatchCounts`,
   `BatchSummary`, `RejectedLine`). Ports are abstract and pure, so the domain purity
   contract still holds; services call them and adapters implement them without either
   importing the other.
4. **Datasets are bind-mounted read-only.** `docker-compose.yml` mounts `./samples` at
   `/app/samples:ro` into `api` and `worker` and sets `SAMPLES_DIR`. Resolution stays
   confined to that directory (T-1.6); nothing else in the stack can see it.
5. **The async path carries ids only** (TB-5). The CLI resolves and checksums the
   dataset, opens the batch row, then enqueues `(batch_id, dataset_id, source_label)`.
   The actor re-resolves the dataset by id, runs the same service against the existing
   batch, and marks it `failed` if the registry refuses. The actor does not retry: ingest
   is idempotent so a re-run is always safe, but a failed batch should be visible as
   `failed` rather than silently re-attempted against a permanent registry error.
6. **Batch-level limits fail the batch; per-line limits never do.** Exceeding
   `INGEST_MAX_LINES` marks the batch `failed`, keeps the valid events already stored and
   raises `IngestLimitExceededError`. Every per-line problem is one `ingest_rejects` row.
   The request-body cap applies to the HTTP path and arrives with it.

## Consequences

- Positive: the use-case is fully unit-tested against an in-memory port
  (`tests/unit/test_ingest_service.py`), and the database suite proves idempotency,
  provenance, rejects and the actor end to end through a `StubBroker`.
- Positive: `make demo-ingest` twice is the acceptance evidence for FR-1.4: the second
  run stores zero events and reports every line as a duplicate.
- Negative: `docs/repo-structure.md` is out of date on `workers/`, `cli.py` (argparse) and
  `domain/ports.py`; it is a planned layout and records this ADR.
- Negative: until Chunk 6, `ingest_batches.actor_user_id` and `actor_token_id` are null
  for every batch, because there is no authenticated actor to record (T-1.8 is complete
  only when the routes exist).
