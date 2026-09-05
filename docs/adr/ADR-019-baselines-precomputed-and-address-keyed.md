# ADR-019 — Baselines are precomputed by a job and reach a rule as address-keyed statistics

- Status: accepted
- Date: 2026-09-05
- Milestone: 2, Chunk 11

## Context

D-005 compares an asset's outbound volume with its own history, and the delivery plan fixes
one constraint: baselines are computed outside detector logic so detectors stay deterministic.
The data model gives `asset_baselines` (per asset, per metric, per window in days). A rule,
however, sees events keyed by IP address and must stay a pure function of its window.

## Decision

1. **A job writes `asset_baselines`; nothing else does.** `BaselineService.recompute` walks every
   active asset's networks, asks the event store for the hourly sum of `bytes_toserver` of flows
   from those networks to non-internal destinations over the last `window_days` complete hours,
   and upserts one row per asset that had any such hour: mean, population standard deviation,
   nearest-rank 95th percentile, and the number of sampled hours. Idle hours are not samples, so
   `sample_count` says how much history the row rests on, and D-005 refuses rows under
   `min_samples`. The job runs from the CLI (`make recompute-baselines`), from the worker
   (`recompute_baselines` actor, queued by `POST /api/v1/detections/baselines/recompute`, admins
   only), and on a schedule from Chunk 12.
2. **The sweep hands baselines to the window, keyed by address.** Before the rules run,
   `DetectionService` lists the outbound baselines, resolves every distinct source address in
   the loaded events through the inventory, and builds `{address: Baseline}` for the addresses
   whose asset has a row. `EventWindow.baselines` carries it into every bucket. The rule reads
   it and does nothing else: no lookup, no clock, no I/O.
3. **"Internal" is an explicit list.** `domain/detectors/addresses.py` names RFC 1918, loopback,
   link-local, carrier-grade NAT, unspecified, multicast and reserved space. Python's
   `is_global` would also call the RFC 5737 documentation ranges non-global, and those are what
   the synthetic corpus and the fixtures use as "the internet". The SQL aggregation and the
   rules share the same list, so the job's history and the rule's window agree on what counts
   as outbound.
4. **Abstain, never guess.** An address without a baseline, a baseline under `min_samples`, or a
   baseline for another metric produces no result. The first-time asset from the evaluation
   plan's hard negatives is therefore silent by construction, and that silence is tested.
5. **Labelled fixtures carry their baselines.** `labels.yml` may list `baselines:` entries; the
   loader puts them on the window, so a D-005 case is reproducible without a database and the
   generator pins the statistics next to the events they judge.

## Consequences

- `EventWindow` gained an optional `baselines` mapping; every existing rule ignores it.
- The event read store gained `hourly_outbound_bytes`, a grouped aggregation the job reads; the
  detection store gained `SqlBaselineStore`.
- Two routes and one permission use grew: `GET /api/v1/detections/baselines`
  (`detections.read`) and `POST /api/v1/detections/baselines/recompute` (`detections.run`).
- Deferred: baselines for the other two metrics in the enum (`distinct_dest_per_hour`,
  `dns_queries_per_hour`), which no rule reads yet; the schedule (Chunk 12).
