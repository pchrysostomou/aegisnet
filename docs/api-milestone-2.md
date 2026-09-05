# AegisNet — Milestone 2 API additions

Status: **Chunks 9, 11 and 12 (alerts, rules, runs, sweeps, baselines, the post-ingest sweep) implemented.**
Conventions, the error envelope, auth and rate limits are those of
[`api-milestone-1.md`](api-milestone-1.md). Permissions: `alerts.read` (viewer and above),
`detections.read` (analyst and above), `detections.run` (admin).

### Alerts (read-only)

**`GET /api/v1/alerts`** — `alerts.read` · newest first by `first_seen`, keyset cursor, page size
≤ 200. Filters: `severity_min` (1–5), `rule_id` (`D-001`), `entity_type`
(`asset|src_ip|dest_ip|domain`), `entity_value`, `status` (`open|correlated|suppressed`), `from`,
`to` (on `first_seen`; `to` must be after `from`).
```json
{ "items": [ { "id": "…", "rule_id": "D-001", "rule_version": 1, "severity": 4, "confidence": 1.0,
  "severity_rationale": { "formula": "…", "base": 3, "asset_criticality": 5, "asset_criticality_source": "asset",
  "signal_strength": 0.6667, "raw": 4.3333, "result": 4 },
  "entity_type": "src_ip", "entity_value": "10.10.0.99", "first_seen": "…", "last_seen": "…",
  "evidence": { "distinct_dest_ports": 40, "distinct_dest_hosts": 1, "flows": 40, "unanswered_flows": 40, "…": "…" },
  "event_count": 40, "status": "open", "dedup_key": "D-001:src_ip=10.10.0.99:2026-09-01T10:00:00+00:00",
  "created_at": "…" } ], "next_cursor": null }
```
Evidence is derived and bounded by construction (ADR-017), which is why viewers may read it.

**`GET /api/v1/alerts/{id}`** — `alerts.read` · the alert plus `events` (`event_id`, `role`
`first|last|peak|sample`, at most 50) and `assets` (`asset_id`, `role` `source|destination`).
`404 not_found` otherwise.

### Detections

**`GET /api/v1/detections/rules`** — `alerts.read` · the registry: `rule_id`, `name`, `version`,
`enabled`, `base_severity`, `window_seconds`, `params`, `description`, `mitre_hint`, `updated_at`.
Seeded from the code on first read if no sweep has run yet.

**`GET /api/v1/detections/runs?limit=`** — `detections.read` · recent runs, newest first, `limit`
1–200: `rule_id`, `window_start`, `window_end`, `events_examined`, `alerts_created`, `status`
(`success|error|skipped`), `error_detail`, `duration_ms`, `created_at`.

**`GET /api/v1/detections/baselines`** — `detections.read` · every `asset_baselines` row: `asset_id`,
`metric`, `window_days`, `mean`, `stddev`, `p95`, `sample_count`, `computed_at` (ADR-019).

**`POST /api/v1/detections/baselines/recompute`** — `detections.run` · body
`{ "window_days": 7 }` (1–90, optional) → `202 { "window_days", "queued": true, "message_id" }`.
The worker summarises each asset's hourly outbound history. Audit: `detection.baselines_requested`.

**`POST /api/v1/detections/sweeps`** — `detections.run` · body `{ "from": "…", "to": "…" }`
(aware timestamps, `to` after `from`, at most 24 hours) → `202 { "window_start", "window_end",
"queued": true, "message_id" }`. The worker runs every rule over the interval (ADR-018); poll
`/detections/runs`. Audit: `detection.sweep_requested`. `422 validation_failed` for a bad interval.

### Sweeps nobody asked for (ADR-020)

A batch that completes with stored events queues `run_detectors` over the hour-aligned span
of its event times: after `import_dataset` and `import_upload` in the worker, and inline after
`POST /api/v1/ingest/eve?mode=sync`, whose `ingest.batch_created` audit entry now carries
`sweeps_queued`. The `scheduler` service sends `scheduled_sweep` every ten minutes over the
last hour and `nightly_baselines` at 02:00. All of them show up as ordinary rows in
`GET /api/v1/detections/runs`; a client that wants to know whether an upload has been judged
polls the runs after the batch reports `complete`.

## Acceptance criteria for the M2 API

- [x] Every new route has an explicit permission dependency (the route-enumeration test covers it).
- [x] Re-running a sweep over the same window creates zero duplicate alerts — `tests/db/test_detection_store.py`, `tests/detectors/test_detection_service.py`.
- [x] Every alert stores `severity_rationale` reproducing its own score — asserted in both suites with `reproduce`.
- [x] A raised exception in one detector is recorded in `detector_runs` and does not stop the others — `tests/detectors/test_detection_service.py`.
- [x] Evidence payloads contain no raw log lines — bounded at construction (`tests/detectors/test_model.py`).
