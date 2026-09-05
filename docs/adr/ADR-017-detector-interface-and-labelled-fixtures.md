# ADR-017 — Detector interface, evidence bounds and labelled fixtures

- Status: accepted
- Date: 2026-09-05
- Milestone: 2, Chunk 8

## Context

Milestone 2 ships five deterministic detectors that must be unit-testable against labelled fixtures,
produce alerts whose severity can be reproduced, never leak a raw log line into evidence, and never
create duplicate alerts on a re-sweep (delivery plan M2, PRD FR-4/FR-5, THREAT_MODEL T-1.7). The
first chunk had to fix the contract every later rule is written against.

## Decision

1. **A detector is a pure object with a `spec` and a `run(window)`.** `domain/detectors/model.py`
   defines `EventWindow` (aware, at most 24 hours and 200 000 events, sorted, every event inside
   `[start, end)`), `DetectionResult`, `Entity`, `EventSample` and `RuleSpec`; `Detector` is a
   Protocol. No I/O, no clock, no randomness inside a rule: the loader bounds the window, the rule
   only reads it. The package lives in `domain/`, so import-linter forbids it any infrastructure.
2. **Evidence is bounded at construction.** `DetectionResult.__post_init__` passes the evidence
   through `bounded_evidence`: scalars and short lists only, 32 keys, 50 items, 128 characters, and
   the keys `raw`, `line`, `raw_line`, `raw_excerpt`, `payload` are refused outright. A rule cannot
   emit a log dump by accident (FR-5.3).
3. **The dedup key is `rule_id:entity_type=entity_value:window_bucket`**, with the bucket the window
   start floored to the rule's `window_seconds`. The alert store (next chunk) makes it unique, so
   sweeping the same interval twice creates nothing the second time.
4. **Severity is computed outside the rule and recorded with its formula.** `severity.score` takes
   the rule's base severity, the rule's signal strength and the asset's criticality (default 3 when
   the entity is not an inventoried asset) and returns the value with a rationale; `reproduce`
   recomputes it from the rationale. Rules emit `signal_strength` and `confidence`, never a severity,
   because criticality needs the inventory and the rule must stay pure.
5. **Labelled fixtures are generated, committed and pinned.** `tools/gen_labelled_fixtures.py`
   renders each case (a short, reviewable description of who talks to whom) into `events.ndjson`
   plus `labels.yml` in the format `docs/evaluation.md` §3 prescribes; a test regenerates them into a
   temporary directory and fails on any byte of drift. Every rule needs at least three positives and
   three negatives, one of them the case a naive implementation gets wrong, named in
   `docs/detection-rules.md` as the reason for a guard.
6. **D-001 counts distinct targets, not connections.** The unit is the `(host, port)` pair per
   source; thresholds are absolute counts of distinct ports and distinct hosts; unanswered flows raise
   confidence. That is the guard the backup-client hard negative demanded.

## Consequences

- Every later rule (D-002 to D-005) inherits the window, evidence, sample and dedup rules for free
  and is specified in `docs/detection-rules.md` before it is written.
- The persisted `detection_rules` registry (next chunk) is seeded from `RuleSpec`, which is what an
  alert is reproducible against; changing a parameter bumps the rule version.
- `make test-detectors` runs the detector suite alone; `make gen-fixtures` regenerates the fixtures
  after a case definition changes, and the pin test forces the regeneration to be committed.
- Deferred: the window loader and sweep service, the alert store, the actors and schedule, the
  `/api/v1/alerts` read API, and the remaining four rules.
