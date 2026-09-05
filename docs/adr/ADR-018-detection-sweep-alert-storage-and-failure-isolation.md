# ADR-018 — The detection sweep: one load, rule-sized buckets, dedup in the database

- Status: accepted
- Date: 2026-09-05
- Milestone: 2, Chunk 9

## Context

ADR-017 fixed what a detector is: a pure function over a bounded `EventWindow`. Something has to
load those windows from PostgreSQL, run every rule, turn results into alerts with a severity the
inventory can inform, refuse duplicates on a re-sweep, record what happened to each rule, and
expose all of it over the API, without a single failing rule taking the others down (delivery plan
M2, ARCHITECTURE §7).

## Decision

1. **A sweep is `[start, end)`, at most 24 hours, loaded once.** `DetectionService.sweep` loads the
   interval's events through `EventWindowStore.load` (oldest first, no payload, at most
   `MAX_WINDOW_EVENTS`) exactly once, then slices them in memory. If the cap cuts the load short,
   every rule is recorded as `skipped` with the reason rather than run over a partial picture.
2. **Each rule sees its own grid.** The interval is split into buckets of the rule's
   `window_seconds`, aligned with `window_bucket`, so the `dedup_key` a result carries does not
   depend on where the operator's interval happened to begin: sweeping 10:03–10:17 and 10:00–10:20
   produce the same keys for the same events.
3. **Dedup is a UNIQUE constraint, not application logic.** `alerts.dedup_key` is unique and
   `SqlAlertStore.create_many` inserts with `ON CONFLICT DO NOTHING`, returning only what was
   created; the sampled `alert_events` and `alert_assets` are written for created rows only. The
   original alert and its links are never touched by a re-sweep.
4. **Severity is computed in the service, with the inventory.** A `src_ip`/`dest_ip` entity is
   resolved through the asset inventory; the asset's criticality feeds `severity.score` and the
   asset is linked with the matching role. Unresolved addresses get the default criticality and the
   rationale says so. The rationale is stored with the alert and reproduces the value.
5. **Failure isolation is per rule and recorded.** Every rule of every sweep writes one
   `detector_runs` row: `success`, `error` (the exception type and a cleaned message, never a
   traceback) or `skipped` (disabled, or the event cap). A raising rule never stops the next one.
6. **The registry is synced from code before each sweep.** `detection_rules` is upserted from
   every registered `RuleSpec` (name, version, base severity, window, params); the operator's
   `enabled` flag is the one column the sync never touches. `detection_rules` is what an alert's
   `rule_version` is reproducible against.
7. **Sweeps run on the worker, are queued over HTTP by admins, and can run inline from the CLI.**
   `POST /api/v1/detections/sweeps` (permission `detections.run`) validates the interval, queues
   `run_detectors(start, end)` on the `detection` queue and audits the request;
   `python -m aegisnet.cli run-detectors --from --to` runs the same service synchronously.
   Alerts, rules and runs are read-only over HTTP (`alerts.read` for viewers and above,
   `detections.read` for runs). The periodic schedule is Chunk 12 (ADR-010).

## Consequences

- Three permissions were added (`alerts.read`, `detections.read`, `detections.run`) and the RBAC
  matrix, the route-enumeration test and `SECURITY.md` grew with them.
- Revision `0003_detection_tables` adds six tables and six enum types; the runtime role gets
  SELECT, INSERT and UPDATE on them and still no DELETE anywhere new. The stack probe and the
  README now expect `0003_detection_tables` from the version route.
- The synthetic corpus raises no alert (it is benign by construction), so the CI stack job proves
  the plumbing (a queued sweep, a `success` run for D-001, readable alerts and rules) and the
  database suite proves detection itself by ingesting a labelled fixture and sweeping it.
- Deferred: alert status changes (M3), the periodic schedule and post-ingest trigger (Chunk 12),
  `asset_baselines` writers (Chunk 11).
