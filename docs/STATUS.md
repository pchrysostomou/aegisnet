# AegisNet — Project Status

**Last updated:** 2026-08-28 · **Current phase:** M0 Planning complete, awaiting M1 chunk-1 approval · **Version:** none tagged

> This file is the single source of truth for progress. It states only what has **evidence**. Nothing below is
> claimed to run, pass, or exist unless an evidence link is given.

---

## Current state

| | |
|---|---|
| Phase | **M0 — Planning complete, implementation not started** |
| Application code written | **None** |
| Tests written | **None** |
| Tests run | **None** |
| Docker stack | **Not built, never started** |
| Database | **No migrations exist** |
| Perplexity integration | **Not implemented; no API call has been made** |
| CI | **No workflow exists** |
| Detector accuracy | **Unmeasured. No claims.** |

## Milestone tracker

| Milestone | Status | Evidence | Notes |
|---|---|---|---|
| M0 Planning | ✅ Complete | This doc set | PRD, architecture, threat model, data model, M1 API, delivery plan, evaluation plan |
| M1 Foundation / ingest / normalize / assets | ⬜ Not started | — | Next up |
| M2 Five detectors + labelled fixtures | ⬜ Not started | — | Blocked on M1 |
| M3 Correlation / incidents / workflow | ⬜ Not started | — | Blocked on M2 |
| M4 Analyst dashboard | ⬜ Not started | — | Blocked on M3 |
| M5 Perplexity brief + Markdown export | ⬜ Not started | — | Blocked on M4 (safe renderer first) |
| M6 Hardening / evaluation / release | ⬜ Not started | — | Gate for `v1.0.0` |

## Definition-of-Done checklist (v1.0.0)

- [ ] `docker compose up --build` starts the full local environment
- [ ] Documented safe sample dataset ingests via one command
- [ ] All five detectors have labelled positive **and** negative test cases
- [ ] Unit + integration tests run in GitHub Actions
- [ ] A reviewer reproduces the main demo from the README alone
- [ ] Architecture, threat model, evaluation results, limitations, screenshots, demo script all exist
- [ ] Auth, RBAC, audit logging, rate limiting implemented and tested
- [ ] Redaction canary suite proves no forbidden data reaches Perplexity
- [ ] `docs/RELEASE_CHECKLIST.md` complete and signed off

## Documents

| Doc | State |
|---|---|
| `README.md` | ⬜ To be written in M1 |
| `ARCHITECTURE.md` | ✅ v0.1 (proposal) |
| `THREAT_MODEL.md` | ✅ v0.1 (planning-phase model; review at every milestone gate) |
| `SECURITY.md` | ⬜ To be written in M1 (RBAC matrix, secret handling, disclosure policy) |
| `docs/PRD.md` | ✅ v0.1 |
| `docs/repo-structure.md` | ✅ v0.1 |
| `docs/data-model.md` | ✅ v0.1 |
| `docs/api-milestone-1.md` | ✅ v0.1 |
| `docs/delivery-plan.md` | ✅ v0.1 |
| `docs/evaluation.md` | ✅ v0.1 plan; **results empty by design** |
| `docs/detection-rules.md` | ⬜ M2 |
| `docs/perplexity-integration.md` | ⬜ M5 |
| `docs/demo-script.md` | ⬜ M6 |
| `docs/RELEASE_CHECKLIST.md` | ⬜ M6 |

## Decisions locked in M0

| ID | Decision |
|---|---|
| D-1 | Background work: **Dramatiq + periodiq** (rationale in `ARCHITECTURE.md` §2) |
| D-2 | Modular monolith backend, strict pure `domain/` layer enforced by import-linter |
| D-3 | Deterministic heuristic detectors only in v1; no ML |
| D-4 | Suricata EVE JSON only in v1; Zeek is a documented future extension |
| D-5 | Primary demo corpus is **committed synthetic EVE**, not a downloaded dataset |
| D-6 | AI briefs are narrative-only and can never mutate detection state |
| D-7 | Events keep promoted typed columns **plus** a validated JSONB payload |
| D-8 | Auth/audit/rate-limit primitives exist from M1; M6 completes and proves them |
| D-9 | **Isolated Suricata Docker lab (`infra/lab/`) deferred to M2.** M1 is file-and-API driven only: no packet capture, no traffic generation, no live-traffic component. Rationale: sensor config, capture permissions, and topology introduce reproducibility risk that would compromise the M1 gates. |

## Open risks being carried

| Risk | Current handling |
|---|---|
| Detector thresholds may need substantial tuning; accuracy is unknown | M2 fixtures + `docs/evaluation.md` measure it honestly before any claim is made |
| Beaconing false positives from legitimate periodic traffic (NTP, updates) | Known-periodic destination allow-list planned in D-004 |
| Indirect prompt injection via log content | Contained, not eliminated — see `THREAT_MODEL.md` R-3 |
| Metadata egress to Perplexity is non-zero even when redacted | Opt-in per incident, off by default, offline mode supported — R-2 |
| Public-dataset licence obligations | Provenance + required citation stored per ingest batch |

## Next actions

1. Execute **M1** per `docs/delivery-plan.md` and the Milestone 1 implementation prompt.
2. Write `README.md` and `SECURITY.md` as part of M1, not after.
3. Update this file at the M1 gate with evidence links (CI run, command transcripts).
