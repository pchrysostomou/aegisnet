# ADR-010 — Defer the scheduler service and periodiq to Milestone 2

- Status: accepted; the deferral ended with ADR-020 (Milestone 2, Chunk 12), which added the
  `scheduler` service alongside the first periodic workload
- Date: 2026-08-28
- Milestone: 1 (decision D-10, flag F-11)

## Context

Decision D-1 selected Dramatiq with periodiq for background work. Periodic scheduling is
only needed once something recurring exists: retention pruning, correlation sweeps, and
beaconing analysis over rolling windows. None of those exist in Milestone 1.

Adding a fifth long-running container in Chunk 1 would mean a scheduler with nothing to
schedule, which is exactly the kind of decorative infrastructure this project is supposed
to avoid.

## Decision

No `scheduler` service and no periodiq dependency in Milestone 1. The Dramatiq **worker**
container is still present because it proves the image, the broker connection, and the
process topology early — but it registers **zero actors** in Chunk 1.

Consequently:

- The worker's Compose healthcheck is process-level liveness only (`pgrep`). It asserts
  that the process is alive and nothing more.
- The worker is not part of `/readyz`. Readiness covers PostgreSQL and Redis only.
- No placeholder actor, heartbeat task, fake queue, or synthetic job is created to make the
  worker appear useful.

The first real actor is EVE normalisation in Chunk 4. Periodiq and the scheduler service
arrive in Milestone 2 alongside the first genuinely periodic workload.

## Consequences

- Positive: nothing in the stack claims a capability it does not have.
- Positive: fewer moving parts to keep healthy while the foundation is being reviewed.
- Negative: a reader may reasonably ask why a worker exists at all in Chunk 1. The answer is
  topology and image validation, and it is stated in the Compose comment, in the broker
  module docstring, and in `docs/STATUS.md`.
- Negative: retention and pruning remain manual until Milestone 2.
