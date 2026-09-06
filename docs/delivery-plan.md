# AegisNet — Six-Milestone Delivery Plan

Rule: a milestone is not "done" until every acceptance criterion has **evidence** — a passing CI run, a command
transcript, or a screenshot committed to the repo. `docs/STATUS.md` is updated at every gate.
Last updated: 2026-08-28

---

## M1 — Foundation, ingest, normalization, asset inventory

**Goal.** A reviewer clones the repo, runs one command, gets a healthy stack, ingests committed synthetic
Suricata EVE JSON, and queries normalized events and assets through an authenticated API.

**Deliverables.** Docker Compose (db, redis, api, worker, web placeholder; the scheduler moved to M2 by ADR-010) · `.env.example` ·
config via pydantic-settings with `SecretStr` · structured logging with secret scrubbing · Alembic baseline
migration for `ingest_batches`, `events`, `ingest_rejects`, `assets`, `asset_networks`, `users`,
`service_tokens`, `refresh_tokens`, `audit_log` · EVE Pydantic schema + normalizer + sanitizer · idempotent
ingest via `event_hash` · asset CRUD + CIDR resolution · read-only event API · minimal login/JWT + per-route
permission dependencies · audit logging · Redis rate limiting · synthetic EVE generator (`tools/gen_synthetic_eve.py`)
+ `samples/registry.yml` · GitHub Actions CI (ruff, mypy, pytest unit+integration+security, coverage gate) ·
`README.md` quickstart, `ARCHITECTURE.md`, `THREAT_MODEL.md`, `SECURITY.md`, `docs/STATUS.md`.

**Architecture decisions locked.** Dramatiq + periodiq for background work · strict `domain/` purity enforced by
import-linter · promoted columns + JSONB payload · dual timestamps · **`infra/lab/` is NOT part of M1** (decision
D-9): no packet capture, no traffic generation, no scanning tooling, no live-traffic component. (The lab arrived
in M2 Chunk 13, ADR-021; scanning tooling never does — `docs/PRD.md` makes it a permanent non-goal.) M1 is file-and-API
driven, proven entirely by the committed deterministic synthetic corpus.

**Security risks addressed.** T-1.1 – T-1.9, T-2.1, T-2.7, T-5.2, T-5.4.

**Acceptance criteria.**
- [x] `docker compose up --build` reaches healthy on a clean clone; `GET /readyz` returns `200` — the CI `stack` job on every push (`docs/STATUS.md` E-38).
- [x] `make seed && make demo-ingest` stores the synthetic batch; a second run adds zero new events — E-32, E-37.
- [x] `events` row counts and `event_type` distribution match the generator's manifest exactly — E-25, E-32 (stats total 2000, per-type counts equal to the manifest).
- [x] Malformed-line, oversized-body, deep-JSON, and path-traversal tests all pass — `tests/security/test_payload_limits.py`, `test_path_traversal.py`, `tests/integration/test_ingest_routes.py` (E-34, E-42).
- [x] Every route has a permission dependency (enumeration test passes) — `tests/security/test_rbac.py` (E-34).
- [x] Ruff, mypy (strict on `domain/`), and pytest green in GitHub Actions — every `ci` run since E-10; latest E-38, E-43.
- [x] No secret appears anywhere in the repo (CI secret scan passes) — the `security` workflow's gitleaks job (E-38).

**Commands.** `cp .env.example .env` → `docker compose up --build -d` → `make migrate` → `make seed` →
`make demo-ingest` → `make test` → `make lint typecheck`.

---

## M2 — Detection engine (five detectors) + labelled fixtures

**Goal.** Five pure, versioned, parameterized detectors run over event windows and emit alerts with bounded
evidence, severity, and asset links — each with labelled positive **and** negative fixtures.

**Also in M2 (moved from M1 by decision D-9).** `infra/lab/docker-compose.lab.yml` — the opt-in isolated Suricata
lab on an `internal: true` network, its sensor config, and lab-only benign traffic generators, plus the
`docs/evaluation.md` §7 pre-flight checklist steps L-0 – L-5 (renumbered from E-0 – E-5 in Chunk 13, because
`docs/STATUS.md` numbers its evidence rows E-1, E-2, … and the two schemes collided).

**Deliverables.** `domain/detectors/` (D-001 port scan, D-002 auth-failure burst, D-003 DNS anomaly/tunnelling,
D-004 beaconing, D-005 outbound volume) + registry · `EventWindow` loader · `severity.py` with a recorded formula ·
Alembic migration for `detection_rules`, `detector_runs`, `alerts`, `alert_events`, `alert_assets`,
`asset_baselines` · baseline recompute job · Dramatiq actors + periodiq schedule for post-ingest and periodic
sweeps · per-detector fixture sets with `labels.yml` · `docs/detection-rules.md` · `/api/v1/alerts` read API.

**Architecture decisions.** Detectors are pure `(window, params) -> list[DetectionResult]` · dedup by
`rule_id:entity:window_bucket` · baselines precomputed outside detector logic so detectors stay deterministic.

**Security risks.** T-1.7 (clock skew affecting windows), detector-exception isolation, DoS via pathological
windows (bounded window size + event caps).

**Acceptance criteria.** Ticked at the M2 gate (2026-09-06, Chunk 13); evidence rows are in `docs/STATUS.md`.
- [x] Each of the five detectors has ≥3 positive and ≥3 negative labelled fixtures; all pass.
      — 34 cases (3 positive and 3 – 4 negative per rule), pinned to their generator;
      `tests/detectors/test_labelled_fixtures.py`, E-49, E-51.
- [x] Every alert stores `severity_rationale` reproducing its own score.
      — `alerts.severity_rationale` is `JSONB NOT NULL` in revision `0003`; the formula and its inputs are
      written with every alert and shown in `make alerts` output. E-47, E-52.
- [x] Re-running a sweep over the same window creates zero duplicate alerts.
      — UNIQUE `alerts.dedup_key` plus `ON CONFLICT DO NOTHING`; asserted hermetically and against
      PostgreSQL (`tests/db/test_detection_store.py`), and observed in the lab run, where a second sweep
      of the same hour created none. E-47, E-54.
- [x] A raised exception in one detector is recorded in `detector_runs` and does not stop the others (test).
      — `tests/detectors/test_detection_service.py::test_one_rule_raising_never_stops_the_others`. E-47.
- [x] Evidence payloads contain no raw log lines — asserted by a shape test.
      — `bounded_evidence()` refuses payload-shaped keys and bounds every value;
      `tests/detectors/test_model.py::test_evidence_keeps_scalars_and_short_lists_only`. E-45.
- [x] Coverage on `domain/detectors/` ≥ 85%.
      — 98% at the gate, inside a repository-wide gate of 85%. E-54.
- [x] **The lab exists, runs, and is safe by declaration and by pre-flight.**
      — `infra/lab/docker-compose.lab.yml` (ADR-021), the L-0 – L-5 checklist ticked in
      `docs/evaluation.md` §7, `backend/tests/security/test_lab_policy.py`, E-54.

**Commands.** `make test-detectors` · `make run-detectors FROM=... TO=...` · `make eval` (first metrics table) ·
`make lab-capture` · `make lab-sanitize` · `make eval-lab` (the T3 qualitative run) · `make test-security`.

---

## M3 — Correlation, incidents, timeline, analyst workflow

**Goal.** Related alerts become incident cases with an ordered timeline and a server-enforced analyst workflow.

**Deliverables.** `domain/correlation.py` (entity + sliding-time-window grouping, escalation on ≥3 distinct
rules) · Alembic migration for `incidents`, `incident_alerts`, `incident_timeline`, `incident_notes` ·
case-number sequence · workflow state machine with validated transitions · `/api/v1/incidents` list/detail/status/
notes · timeline assembly · audit entries for every transition · correlation integration tests over multi-detector
scenarios.

**Architecture decisions.** Correlation is deterministic and re-runnable; alerts may join an existing open
incident rather than always creating a new one; closed incidents never absorb new alerts (a new case is created
and cross-referenced).

**Security risks.** T-2.2 (IDOR on incident ids), T-2.3 (illegal transitions), T-2.5 (audit non-repudiation).

**Acceptance criteria.**
- [x] A scripted multi-stage synthetic scenario (scan → auth failures → beaconing → large upload from one asset)
      produces exactly one incident with four alerts from four distinct rules and an escalated severity —
      `samples/scenarios/multi-stage-01.ndjson`, asserted in `tests/detectors/test_demo_scenario.py` and run
      end to end by `make demo-scenario` (Chunk 17, ADR-025; on the stack: `AEG-2026-0003`, severity 5).
- [x] Timeline entries are ordered, typed, and include the status changes made during the test — `tests/integration/test_incident_routes.py`, over the real router (Chunk 16).
- [x] Every invalid transition returns `409` and is audit-logged as `denied` — `tests/integration/test_incident_routes.py`; the route audits `incident.status_change_refused` before re-raising (Chunk 16).
- [x] Correlation is idempotent: re-running adds no duplicate incident-alert links — `tests/db/test_incident_store.py`, including the non-regression that the `ON CONFLICT` survived Chunk 16's split of the append path.
- [x] RBAC: `viewer` receives `403` on all mutations — the matrix test runs all six incident routes against all four roles (Chunk 16).

**Commands.** `make demo-scenario` · `make test-correlation`.

---

## M4 — Analyst dashboard (Next.js)

**Goal.** A working analyst UI: incident list, incident detail with timeline and evidence, workflow controls,
asset views — safe rendering throughout.

**Deliverables.** Next.js App Router app · login + token refresh handling · incident table with severity/status/
asset/rule filters · incident detail (timeline, alert cards, evidence tables, paginated event drill-down) ·
status control + notes · asset management screens · audit viewer (admin) · `SafeMarkdown` strict-allow-list
renderer · zod schemas mirroring backend DTOs · ESLint rule banning `dangerouslySetInnerHTML` · Playwright smoke
tests · committed screenshots.

**Architecture decisions.** Server components for lists (no client-side data sprawl) · the frontend never
touches the database · all severity/status logic is display-only, computed server-side.

**Security risks.** T-1.3 (stored XSS from log content), T-2.4 (token handling), T-4.4 (hostile markdown —
renderer built here, before the AI feature lands).

**Acceptance criteria.**
- [x] A stored-XSS fixture (malicious DNS query and HTTP host) renders as inert text — Playwright asserts no
      script execution and no `innerHTML` injection (Chunk 20, `frontend/e2e/xss.spec.ts`; ADR-028).
- [x] Incident list and detail render the M3 demo scenario correctly; screenshots committed to `docs/screenshots/` — generated by `pnpm e2e:shots` (Chunk 20).
- [x] `viewer` sees no mutation controls and receives `403` if requests are forged — verified on the running stack (Chunk 19; `docs/STATUS.md` E-66).
- [x] Keyboard navigation works on list, detail, and status controls; WCAG AA contrast verified — `e2e/keyboard.spec.ts` and `src/app/contrast.test.ts`, which computes the ratios from the stylesheet (Chunk 20).
- [x] `tsc`, ESLint, vitest, and `next build` green in CI — the `frontend` job runs all four (Chunk 18, ADR-026).

**Commands.** `make up` · `pnpm --dir frontend test` · `pnpm --dir frontend exec playwright test`.

---

## M5 — Perplexity investigation brief + Markdown export

**Goal.** Generate a redacted, schema-validated, citation-checked AI investigation brief per incident, and export
the case as a Markdown report.

**Deliverables.** `domain/redaction/` (pseudonymizer, denylist scanner, `CaseEvidencePacket` builder) ·
`adapters/perplexity/` (hardened client: timeout, bounded retries with jitter, response cache keyed on
`packet_hash`, budget guard, header scrubbing) · `InvestigationBrief` response schema + citation resolution +
safety filter · Alembic migration for `investigation_briefs`, `brief_citations` · `POST /api/v1/incidents/{id}/brief`,
`GET .../briefs`, `GET .../briefs/{version}` · `GET /api/v1/incidents/{id}/report.md` deterministic renderer ·
`BriefPanel` + `CitationList` + `UnverifiedTag` UI · offline demo mode using a committed fixture response ·
`docs/perplexity-integration.md`.

**Architecture decisions.** Allow-list serialization only — no ORM object or raw payload can reach the request
body · briefs are immutable and versioned · briefs are narrative only and can never mutate alert or incident
fields · offline mode so a reviewer without an API key still sees the feature.

**Security risks.** The whole of TB-3 and TB-4: T-3.1 – T-3.6, T-4.1 – T-4.5.

**Acceptance criteria.** All eight are met as of Chunk 24, which closes Milestone 5. The feature remains **off by
default and no outbound call has ever been made from this repository**: every test runs against committed fixtures
through a mock transport, and a checkout without a key is served the offline sample.

- [x] **Canary redaction test passes:** every event field poisoned with canary emails, secrets, AWS-style keys, and
      private-key blocks; none appear in the serialized request body — 36 tests in
      `backend/tests/security/test_redaction.py`, asserting against the serialised body rather than the object
      (Chunk 21, ADR-029, `docs/STATUS.md` E-70). The suite found a real leak on its first run.
- [x] Serialized packet stays under the configured byte cap; truncation is flagged in `packet_truncated` — Chunk 21
      (E-70), surfaced on the brief and in the dashboard panel from Chunk 24.
- [x] A prompt-injection corpus embedded in DNS/HTTP fields cannot alter any alert or incident field — structurally in
      Chunk 21 (what leaves is arithmetic, not prose) and asserted at the route in Chunk 23, which compares the whole
      case before and after generating a brief (E-70, E-74).
- [x] A fixture response with an uncited external claim is stored and rendered as `UNVERIFIED` — stored in Chunk 22
      (E-72), rendered in Chunk 24 by `UnverifiedTag` in the dashboard and by the report's own marker
      (`backend/tests/unit/test_reports.py`, `frontend/src/components/brief-panel.tsx`).
- [x] A fixture response recommending an offensive/automated action is rejected as `safety_rejected` — Chunk 22
      (ADR-030, E-72); the filter is a step after validation, not a pydantic validator, which is what makes the
      reason distinguishable.
- [x] Timeout, 429, 5xx, and malformed-JSON responses each produce a graceful `failed` brief with the incident
      still fully usable — every reason named and tested in Chunk 22 (E-72), stored as a brief and answered `201` in
      Chunk 23 (E-74).
- [x] Exported Markdown is byte-identical across two runs for the same incident — Chunk 24 (ADR-032):
      `backend/tests/unit/test_reports.py` shuffles every collection, moves dictionary keys and strips timezones;
      `backend/tests/integration/test_report_routes.py` exports twice over HTTP and compares bytes; and
      `frontend/e2e/briefs.spec.ts` does the same against a running stack. The export writes nothing to the case,
      which is what makes it true.
- [x] No API key appears in any log record — Chunk 22 (E-72): the key is a `SecretStr` carried only in a header, a
      transport failure records the exception's *type*, and the value is in `secret_values()` so the scrubber would
      catch it even if the client were wrong.

**Commands.** `make brief REF=AEG-2026-0001` · `make test-security` · `make export REF=AEG-2026-0001`.
(Both were planned as `INCIDENT=`; every neighbouring case-scoped target uses `REF=`, and these match them.)

---

## M6 — Hardening, evaluation, documentation, release

**Goal.** Earn the v1.0.0 label: full auth/RBAC/audit/rate-limit hardening, published evaluation results,
complete documentation, reproducible demo.

**Deliverables.** Full RBAC permission matrix + parametrized matrix test · refresh-token rotation with reuse
detection · account lockout · least-privilege Postgres roles and audit-table grants · rate-limit tuning ·
container hardening (non-root, read-only rootfs, dropped caps, pinned digests) · `pip-audit`/`npm audit`/image
scan in CI · retention job · `docs/evaluation.md` with per-detector precision/recall/F1 · `docs/demo-script.md`
(≤3 minutes) · screenshots · `docs/adr/` populated · `CHANGELOG.md` · `docs/RELEASE_CHECKLIST.md` · threat-model
review pass · tag `v1.0.0`.

**Acceptance criteria.**
- [ ] RBAC matrix test covers every route × every role, with no unexpected allows.
- [ ] Audit log proves non-repudiation: DB grant test confirms the app role cannot `UPDATE`/`DELETE` `audit_log`.
- [x] Rate limits verified under a load test; `429` + `Retry-After` correct — `make load-test`
      (Chunk 26): 120 of 180 concurrent reads allowed, the refusals carrying the documented envelope and a
      `Retry-After` inside the window, login refused after five wrong passwords, and the fixed-window edge
      measured at exactly 2× the limit. Numbers and their limits in `docs/evaluation.md` §10.
- [ ] All containers run as non-root; compose publishes only `127.0.0.1` ports (verified test).
- [ ] `docs/evaluation.md` reports precision/recall for all five detectors on the labelled corpus, with the
      command used and the corpus commit sha.
- [ ] A fresh-clone reproduction run by following only the README succeeds; transcript committed.
- [ ] Coverage gates met (≥85% on `domain/`, ≥70% overall).
- [ ] Every `THREAT_MODEL.md` mitigation maps to a named passing test or an accepted-risk entry.
- [ ] Release checklist fully ticked, then `v1.0.0` tagged.

**Commands.** `make ci-local` · `make eval` · `make load-test` · `make release-check`.

---

## Sequencing rationale

Detection (M2) precedes correlation (M3) because correlation is meaningless without real alerts. The dashboard
(M4) precedes the AI feature (M5) so the safe-markdown renderer and the untrusted-text rendering path already
exist before untrusted LLM output arrives. Hardening (M6) is last but its *primitives* (auth dependency, audit
writes, rate limiting) are built in M1 — M6 completes and proves them rather than introducing them, so no
milestone ever ships an unauthenticated endpoint.
