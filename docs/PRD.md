# AegisNet — Product Requirements Document (v1.0 target)

Status: **Delivered at `v1.0.0`.** §8's ten acceptance criteria are ticked against the same evidence
rows `docs/STATUS.md` carries. §3's non-goals are permanent, and the lab suite enforces the
offensive-tooling one directly (`test_the_lab_contains_no_offensive_tooling`).
Owner: Makis · Last updated: 2026-09-06 (Chunk 31, the release gate)

---

## 1. Problem statement

Small teams and home-lab operators can run Suricata and collect network telemetry, but the raw output is
unusable as an investigation surface. `eve.json` is a firehose of per-event records with no asset context,
no severity model tied to business criticality, no grouping of related activity, and no narrative. Analysts
end up grepping JSON and rebuilding the same mental timeline every time.

AegisNet closes the gap between *raw detection telemetry* and *a reviewable investigation case*.

## 2. Product goal

A self-hosted, reproducible, defensive-only platform that:

1. ingests safe Suricata EVE JSON (isolated Docker lab traffic or public/synthetic datasets),
2. normalizes it into a queryable PostgreSQL schema,
3. enriches events with a local asset inventory,
4. runs five deterministic, testable behavioural detectors,
5. correlates alerts into incident cases with a timeline,
6. presents cases in a Next.js analyst dashboard with a workflow state machine,
7. generates a **redacted, evidence-grounded, citation-bearing** AI investigation brief via the Perplexity API,
8. exports a case as a Markdown incident report.

## 3. Explicit non-goals (safety boundary)

These are permanent product constraints, not deferred features.

| Non-goal | Rationale |
|---|---|
| No scanning, probing, enumeration, exploitation, or brute-forcing of any host | Offensive capability is out of scope by charter |
| No automated blocking, firewall/ACL changes, host isolation, account disable/lockout | AegisNet never performs real-world response actions |
| No live capture from networks the operator does not own | Legal and ethical boundary |
| No IPS/inline mode | Detection and analysis only |
| No raw PCAP, credentials, email addresses, secrets, or unrestricted log text leaving the deployment | Data-egress control (see `docs/perplexity-integration.md`) |
| No multi-tenant SaaS, no billing, no external user signup | Single-team self-hosted scope |
| No ML/deep-learning classifier in v1 | Deterministic, explainable heuristics only; ML deferred to v2 backlog |
| No Zeek ingestion in v1 | Documented future extension via the same normalizer interface |

Containment output is **advisory text for human review only**. The word "recommendation" in this product
never implies an executable action.

## 4. Users and jobs-to-be-done

| Persona | Job | Success signal |
|---|---|---|
| **Lab analyst** (primary) | "Show me what looks wrong on my lab network and why." | Opens a case, understands the story in under 2 minutes without reading raw JSON |
| **Detection engineer** | "Change a detector threshold and prove I did not break anything." | Edits rule params, runs `pytest`, sees labelled positive/negative fixtures still pass |
| **Reviewer / hiring manager** | "Clone this and reproduce the demo." | `docker compose up --build`, seed, follow README, sees populated dashboard |
| **Admin** | "Control who can ingest, who can read, who can call the AI." | RBAC roles enforced; every sensitive action in the audit log |

## 5. Functional requirements

### FR-1 Ingestion
- FR-1.1 Accept Suricata EVE JSON via authenticated API (`POST /api/v1/ingest/eve`), NDJSON body or multipart file.
- FR-1.2 Accept a server-side file import from a whitelisted directory (`samples/`) — no arbitrary path traversal.
- FR-1.3 Enforce max payload size, max lines per batch, and per-token rate limits.
- FR-1.4 Every ingest is idempotent: a stable `event_hash` prevents duplicate rows on re-ingest.
- FR-1.5 Malformed lines are rejected individually and counted; a bad line never fails the whole batch.
- FR-1.6 Every ingest creates an `ingest_batch` record with source label, counts, and dataset provenance.

### FR-2 Normalization
- FR-2.1 Map EVE common fields — `timestamp`, `flow_id`, `event_type`, `src_ip`, `src_port`, `dest_ip`, `dest_port`, `proto`, `app_proto` — into typed columns ([Suricata EVE JSON format](https://docs.suricata.io/en/latest/output/eve/eve-json-format.html)).
- FR-2.2 Map `event_type`-specific sub-objects (`alert`, `dns`, `http`, `flow`, `tls`, `fileinfo`, `anomaly`) into a validated JSONB payload plus a small set of promoted columns used by detectors.
- FR-2.3 Preserve Suricata's own `alert.signature`, `alert.signature_id`, `alert.category`, `alert.severity` as *signature evidence*, distinct from AegisNet detector alerts.
- FR-2.4 Reject/quarantine events failing Pydantic validation into `ingest_rejects` with a reason code.

### FR-3 Asset inventory
- FR-3.1 CRUD assets with: `hostname`, `ip` / `cidr`, `environment` (lab|dev|staging|prod-sim), `owner`, `criticality` (1–5), `tags[]`.
- FR-3.2 Resolve events to assets by IP/CIDR match at detection time; unmatched IPs become `unknown` observed endpoints, never silently dropped.
- FR-3.3 Asset criticality is an input to severity scoring.

### FR-4 Detectors (five, all deterministic and windowed)
1. **D-001 Port scan** — one source touching many distinct destination ports/hosts in a short window.
2. **D-002 Auth-failure burst** — repeated authentication-failure indicators from one source against one service.
3. **D-003 DNS anomaly / possible tunnelling** — high-entropy or over-long labels, excessive NXDOMAIN, abnormal query volume per domain.
4. **D-004 Periodic beaconing** — low-jitter, regular-interval outbound connections to a single destination.
5. **D-005 Outbound volume anomaly** — outbound bytes far above the rolling baseline for that asset.

Each detector: pure function over a bounded event window → zero or more `DetectionResult`. No I/O inside
detector logic, so every detector is unit-testable against fixtures. Full specs in `docs/detection-rules.md`.

### FR-5 Alerts
- FR-5.1 Alert carries: `rule_id`, `rule_version`, `severity`, `confidence`, `first_seen`, `last_seen`, structured `evidence` JSONB, linked asset(s), and the contributing `event_id`s.
- FR-5.2 Severity = f(rule base severity, asset criticality, signal strength), clamped 1–5, and the formula is recorded in the alert for auditability.
- FR-5.3 Evidence is *derived and bounded* (counts, ports, intervals, sampled event ids) — never a raw log dump.

### FR-6 Correlation into incidents
- FR-6.1 Group alerts into an `incident` by shared entity (asset / src_ip / dest_ip) within a sliding time window.
- FR-6.2 Incident severity = max of member alert severities, with an escalation bump when ≥3 distinct rule ids implicate the same asset.
- FR-6.3 Incident timeline = ordered, typed events: alerts, key observations, analyst state changes, brief generation.
- FR-6.4 Analyst workflow states: `new → triaging → investigating → contained_recommended → closed_true_positive | closed_false_positive | closed_benign`. Transitions validated server-side and audit-logged.

### FR-7 Dashboard
- FR-7.1 Incident list: severity, status, asset, rule mix, time range, filter/sort.
- FR-7.2 Incident detail: timeline, alert cards with evidence tables, linked assets, raw-event drill-down (paginated, redaction-aware).
- FR-7.3 Analyst actions: change status, add note, request AI brief, export Markdown.
- FR-7.4 Read-only viewers cannot mutate state or trigger AI briefs.

### FR-8 Perplexity investigation brief
- FR-8.1 Build a `CaseEvidencePacket` — redacted, schema-defined, size-capped — from the incident.
- FR-8.2 Call the Perplexity API with timeout, bounded retries with jitter, and a content-hash cache.
- FR-8.3 Validate the response against `InvestigationBrief` with required sections: observed facts, hypotheses, confidence & uncertainty, evidence gaps, safe triage steps, safe containment recommendations for human review, external research claims with citations, limitations.
- FR-8.4 Any external-intelligence claim without a resolvable citation URL is stored and rendered as **UNVERIFIED**.
- FR-8.5 Briefs are versioned and immutable; regeneration creates a new version.
- FR-8.6 Failure is graceful: incident remains fully usable without a brief.

### FR-9 Export
- FR-9.1 `GET /api/v1/incidents/{id}/report.md` renders a deterministic Markdown incident report: summary, assets, timeline, alerts + evidence, AI brief (with verification status), limitations, appendix of dataset provenance.

### FR-10 Platform security (required *before* the v1.0 label)
- FR-10.1 Authentication: local users, Argon2id password hashing, short-lived JWT access + rotating refresh tokens; service tokens for ingest.
- FR-10.2 RBAC roles: `admin`, `analyst`, `viewer`, `ingest_service` — permission matrix in `SECURITY.md`.
- FR-10.3 Audit log: actor, action, target, timestamp, source IP, result — append-only, for every auth event, state change, ingest, AI call, and export.
- FR-10.4 Rate limiting: per-token and per-IP, stricter on ingest and AI-brief endpoints.

## 6. Non-functional requirements

| Area | Target |
|---|---|
| Reproducibility | `docker compose up --build` yields a working stack from a clean clone on Linux/macOS |
| Ingest throughput | ≥ 5,000 EVE events/minute on 2 vCPU / 8 GB (sufficient for lab + sample datasets) |
| API latency | p95 < 300 ms for incident list/detail at 10k events, 1k alerts |
| Test coverage | ≥ 85% on `detectors/`, `correlation/`, `redaction/`; ≥ 70% overall |
| CI | Ruff, mypy (strict on core modules), pytest unit + integration on every PR |
| Data egress | Zero raw log text or PCAP to any external service; enforced by a redaction test suite |
| Observability | Structured JSON logs with correlation ids; secrets and PII never logged |
| Accessibility | Dashboard keyboard-navigable, WCAG AA contrast |

## 7. Key product decisions and defaults

| Decision | Choice | Rationale |
|---|---|---|
| Detection paradigm | Deterministic windowed heuristics | Explainable, testable, gradeable against labelled fixtures; ML would make evaluation and evidence far weaker |
| Detector execution | Batch sweep over event windows after ingest + periodic scheduled sweep | Simpler and more testable than true streaming; matches lab/dataset use |
| Time model | All timestamps stored UTC `timestamptz`, and the dashboard renders UTC too — deliberately not the reader's locale (`frontend/src/components/timestamp.tsx`) | Avoids the classic correlation-off-by-an-hour class of bug: an analyst comparing a case against a capture or an audit row is comparing against UTC, and a dashboard that quietly shifted times would make them do the arithmetic in their head at the wrong moment |
| Baselines | Rolling per-asset statistics table, recomputed on a schedule | Needed by D-005; keeps detector logic pure |
| AI role | Narrative synthesis + external context only | The AI never detects, scores, or decides; detection stays deterministic and auditable |
| Multi-tenancy | Out of scope | Keeps auth model and threat model tractable |

## 8. Acceptance criteria for v1.0 (Definition of Done)

- [x] `docker compose up --build` starts api, worker, scheduler, postgres, redis, web — all healthchecked. Six services, six healthchecks; proven on a clean clone in `docs/fresh-clone-transcript.txt` and on every CI `stack` run.
- [x] A documented safe sample dataset ingests via one README command — `make demo-ingest`; a second run stores nothing and reports 2000 duplicates.
- [x] All five detectors have labelled **positive and negative** fixtures; precision/recall reported in `docs/evaluation.md` §8 — 34 cases, 15 positive and 19 negative, written by `make eval` and pinned by a test. Synthetic data only; §8 says so above its own table.
- [x] Unit + integration tests pass in GitHub Actions on push and PR — thirteen checks green on the tagged commit (E-95).
- [x] A reviewer reproduces the main demo from the README with no undocumented steps — `docs/fresh-clone-transcript.txt`. It hit one undocumented step, a database volume outliving its checkout; that is now documented and warned about, which is what closed this box.
- [x] `README.md`, `ARCHITECTURE.md`, `THREAT_MODEL.md`, `SECURITY.md`, `docs/STATUS.md`, `docs/detection-rules.md`, `docs/evaluation.md`, `docs/perplexity-integration.md` all current. — all eight exist and were re-read against the code in Chunk 31's claims audit, which found nineteen stale statements in them.
- [x] Screenshots + a ≤3-minute demo script exist — `docs/screenshots/` (queue, case, assets, generated by one command) and `docs/demo-script.md`, whose timings were measured on the fresh-clone run.
- [x] Auth, RBAC, audit logging, rate limiting implemented and tested — Chunk 6, with 144 RBAC matrix cases and the audit-log grant refused by PostgreSQL itself.
- [x] Redaction test suite proves no forbidden field class can reach the Perplexity request body — `tests/security/test_redaction.py` asserts against the **serialised body** and found a real leak on its first run (ADR-029).
- [x] `docs/RELEASE_CHECKLIST.md` completed and signed off before tagging `v1.0.0` — Chunk 31, with one box deliberately left unticked and its reason beside it.

## 9. Out-of-scope backlog (post-v1)

Zeek JSON ingestion · ML anomaly scoring · MITRE ATT&CK technique mapping · SSO/OIDC · alert suppression &
tuning workflow · Sigma rule import · multi-node deployment · notification channels · case assignment and SLA
tracking.

---

### Dataset provenance note

Public datasets carry licence and citation obligations that AegisNet must record per ingest batch.
CIC-IDS2017 is published for researchers and requires citing its source paper
([Canadian Institute for Cybersecurity](https://www.unb.ca/cic/datasets/ids-2017.html)). UNSW-NB15 grants free
use for academic research in perpetuity, requires author agreement for commercial use, and requires citing five
listed papers ([UNSW Canberra](https://research.unsw.edu.au/projects/unsw-nb15-dataset)). The primary v1 demo
path therefore uses **synthetic EVE JSON generated in-repo** plus locally generated isolated-lab traffic, with
public datasets as an optional documented extra.
