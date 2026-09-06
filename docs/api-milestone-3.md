# AegisNet — Milestone 3 API additions

Status: **Chunk 16 (incidents: list, detail, timeline, notes, status transitions) implemented.**
Conventions, the error envelope, auth and rate limits are those of
[`api-milestone-1.md`](api-milestone-1.md). Permissions: `incidents.read` (viewer and above),
`incidents.write` (analyst and above). The workflow itself is
[ADR-023](adr/ADR-023-correlation-and-incidents.md); how it is enforced over HTTP is
[ADR-024](adr/ADR-024-incident-api-workflow-enforcement-and-analyst-text.md).

### The workflow

A case is `new` when correlation opens it. From there:

| From | May become |
| --- | --- |
| `new` | `triaging`, `investigating`, any closed status |
| `triaging` | `investigating`, `contained_recommended`, any closed status |
| `investigating` | `triaging`, `contained_recommended`, any closed status |
| `contained_recommended` | `investigating`, any closed status |
| `closed_true_positive`, `closed_false_positive`, `closed_benign` | `investigating` only |

Closed is not final: a case reopens, but only to `investigating`, never back to `new` — that
would erase the fact that somebody had already looked at it. Moving a case to the status it
already holds is refused rather than ignored, because a client that has lost track should be
told so. The current row's legal moves are on the detail response as `allowed_transitions`, so
a client never keeps its own copy of this table.

### Incidents

**`GET /api/v1/incidents`** — `incidents.read` · newest first by `created_at`, keyset cursor,
page size ≤ 200. Filters: `status`, `open` (`true` hides closed cases), `severity_min` (1–5),
`correlation_key` (`src_ip=10.10.0.42`).
```json
{ "items": [ { "id": "…", "case_number": "AEG-2026-0001",
  "title": "3 rules on 203.0.113.20: D-001, D-003, D-004", "severity": 4,
  "severity_rationale": { "formula": "min(5, max(member severities) + (1 if distinct rules >= 3 else 0))",
  "member_max": 3, "distinct_rules": 3, "escalated": true, "result": 4 },
  "status": "new", "primary_asset_id": null, "correlation_key": "src_ip=203.0.113.20",
  "window_start": "…", "window_end": "…", "distinct_rule_count": 3, "assigned_to": null,
  "closed_at": null, "closure_reason": null, "created_at": "…", "updated_at": "…" } ],
  "next_cursor": null }
```

**`GET /api/v1/incidents/{id}`** — `incidents.read` · the case, plus `alerts` (the linked
alerts in full, oldest first, in the shape `GET /alerts` returns), `timeline` (the newest 200
entries, in the order they happened), `timeline_truncated`, and `allowed_transitions`.
`404 not_found` otherwise. A timeline entry is:
```json
{ "id": "…", "occurred_at": "…", "entry_type": "status_change", "summary": "Status changed from new to triaging",
  "detail": { "from": "new", "to": "triaging" }, "alert_id": null, "actor_user_id": "…", "created_at": "…" }
```
`entry_type` is one of `alert_fired`, `observation`, `status_change`, `note_added`,
`brief_generated`, `report_exported`, `asset_linked`.

**`GET /api/v1/incidents/{id}/timeline?limit=&cursor=`** — `incidents.read` · the whole story,
oldest first, keyset-paginated. This is how a case longer than the detail's 200 entries is read.

**`POST /api/v1/incidents/{id}/status`** — `incidents.write` · body
`{ "status": "triaging" }`, or `{ "status": "closed_benign", "closure_reason": "known backup job" }`
(≤ 500 characters, and only on a closing status — otherwise `422`). Answers `200` with the same
body as the detail route.

Writes an `incident_timeline` entry of type `status_change` carrying `from`, `to` and, when
closing, the reason; and an audit entry `incident.status_changed`. A move the workflow forbids —
including a move to the status the case already holds — answers `409 conflict` and is audited as
`incident.status_change_refused` with `result: denied`. A move whose starting status somebody
else changed first answers `409` as well, audited with `reason: status_changed_concurrently`;
nothing is written, and the analyst re-reads the case rather than overwriting a decision they
never saw.

Closing stamps `closed_at` and stores the reason; reopening clears both. The reason survives in
the timeline, which is where a case's history lives.

**`POST /api/v1/incidents/{id}/notes`** — `incidents.write` · body `{ "body": "…" }`, 1–8 000
characters → `201` with the stored note. Control characters are stripped, tab and newline kept,
surrounding whitespace trimmed; a note that is empty once cleaned, or too long, is refused with
`422 validation_failed` naming `body` rather than being silently truncated. Notes are never
edited or deleted.

Writes a `note_added` timeline entry whose summary is `"Note added"` and whose detail is
`{ note_id, length }`, and an audit entry `incident.note_added` with the same. **The body itself
is never copied into the timeline, the audit log or a log line** — one place holds an analyst's
words, and it is the one nothing rewrites (ADR-024).

**`GET /api/v1/incidents/{id}/notes?limit=&cursor=`** — `incidents.read` · newest first,
keyset-paginated, bodies in full.

### Audit actions this milestone adds

| Action | Result | Written when |
| --- | --- | --- |
| `incident.status_changed` | `success` | a case moved; detail carries `case_number`, `from`, `to`, `closure_reason_chars` |
| `incident.status_change_refused` | `denied` | a move was refused; detail carries `from`, `to`, `reason` (`illegal_transition` or `status_changed_concurrently`) |
| `incident.note_added` | `success` | a note was written; detail carries `note_id` and `length`, never the text |
| `rbac.denied` | `denied` | a viewer attempted any of the two write routes |

## Acceptance criteria for the M3 API

- [x] Every new route has an explicit permission dependency — the route-enumeration test in `tests/security/test_rbac.py` covers all six.
- [x] Every invalid transition returns `409` and is audit-logged as `denied` — `tests/integration/test_incident_routes.py`.
- [x] RBAC: `viewer` receives `403` on all mutations — the matrix test runs every route against all four roles.
- [x] Timeline entries are ordered, typed, and include the status changes made during the test — asserted over HTTP against the real router.
- [x] Correlation is idempotent and unaffected by the new write path — `tests/db/test_incident_store.py` proves the `ON CONFLICT` still no-ops after `_append_one` was split out.
- [ ] A scripted multi-stage scenario produces exactly one incident with four alerts from four distinct rules — Chunk 17 (`make demo-scenario`).
