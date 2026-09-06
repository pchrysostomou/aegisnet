# ADR-024 — Enforcing the workflow over HTTP, and what an analyst's words are allowed to touch

- Status: accepted
- Date: 2026-09-06
- Milestone: 3 (Chunk 16); builds on [ADR-023](ADR-023-correlation-and-incidents.md)

## Context

ADR-023 made an incident: alerts about one entity, a case number, a derived severity, an
append-only timeline, and a workflow written as a table in `domain/incidents.py`. Nothing
could reach any of it except the CLI, and nothing could move a case at all.

Chunk 16 opens the case to analysts. That turns three questions that were theoretical into
decisions the code has to make. Who may change a case, and what happens when somebody who may
not tries. What happens when two analysts change the same case in the same second — which is
not an exotic race but the ordinary shape of a shift handover. And where an analyst's own
words are allowed to end up, given that this project keeps an append-only audit log
specifically so that a later reader can trust it.

The M3 acceptance criteria fix two of the answers already: every invalid transition returns
`409` and is audit-logged as `denied`, and a `viewer` receives `403` on all mutations.

## Decision

### The workflow is enforced by the database, not by a prior read

A status change is one statement:

```sql
UPDATE incidents SET status = :target, closed_at = …, closure_reason = …, updated_at = :now
 WHERE id = :id AND status = :expected
RETURNING id
```

The status the caller believed the case was in is part of the `WHERE`. If somebody else moved
the case in between, no row matches, the store returns `None`, and the service raises
`StatusRefusedError` with `reason="status_changed_concurrently"`. The alternative — read the
case, check the transition, then write — has a window between the check and the write in which
the second analyst's judgement silently replaces the first's with no record that two were
made. The table in `domain/incidents.py` still decides *which* moves are legal; the database
decides *whether this particular caller is still entitled to make one*.

`closed_at` and `closure_reason` move in that same statement rather than a following one,
because `ck_incidents_closed_at_matches_status` is an equality in both directions: a closing
status demands a timestamp and every other status demands its absence. Two statements would
mean a moment where the row is invalid, and PostgreSQL would refuse the first one anyway.

A refusal is a refusal, not an error. `StatusRefusedError` subclasses the domain's
`IllegalTransitionError`, which `api/errors.py` maps to `409 conflict`, so a refused change
cannot become a `500` by arriving through a class nobody registered.

### A change is recorded twice, on purpose

Every status change writes an `incident_timeline` row inside the transaction that changed the
status, and an `audit_log` row after that transaction commits. This is deliberate duplication,
and each copy answers a different question.

The timeline is the case's story: what happened, in the order it happened, for a human reading
the case months later. The audit log is evidence: who did it, from where, under which
correlation id, in a table the runtime role can `SELECT` and `INSERT` but never `UPDATE` or
`DELETE` (ADR-012). The timeline is written first and inside the transaction so a case can
never be in a status its own story does not explain. The audit row is written afterwards so it
can never claim a change that did not commit.

The route writes the audit row, not an exception handler. `api/deps.py` says why: a FastAPI
exception handler cannot see what a dependency resolved, so a handler has no principal, and a
denial nobody can attribute is not a denial record. The route catches `StatusRefusedError`,
records `incident.status_change_refused` with `result=denied`, and re-raises — the shape
`api/v1/ingest.py` already uses for a refused upload.

### An analyst's words live in exactly one place

A note is stored whole in `incident_notes`. Its timeline line says `"Note added"` and carries
`{note_id, length}`. Its audit entry carries the same. The body itself appears nowhere else.

Three reasons, in order of weight. The audit writer caps a string at 512 characters and strips
newlines, so an audited copy of an 8 000-character note would silently differ from the note —
a second version of the truth in the table that exists to be trusted. A key-based secret filter
cannot help with free text, so a credential pasted into a note would become permanent in a
table nothing is allowed to rewrite. And the timeline is `UPDATE`-granted, so a copy of the
prose there is a copy that can drift from the note it quotes.

`closure_reason` is treated the other way round, and the difference is the point. It lives on
the case *and* in the `status_change` timeline entry's detail, because reopening a case clears
the column: without the timeline copy, the reason somebody closed a case would be destroyed by
the next person who reopened it. The audit entry records `closure_reason_chars` rather than the
text, so a later truncation would be visible.

Both are cleaned by `domain/incidents.clean_note_body` and `clean_closure_reason` — control
characters stripped, tab and newline kept, whitespace trimmed — and **refused rather than
truncated** when too long. `domain/eve/sanitize.clean_text` strips the newline too, which is
right for a log line being squeezed into one field and wrong for a note somebody wrote in
paragraphs; the two rules differ by exactly that character and each says so.

### A viewer reads a case; an analyst changes one

`incidents.read` sits in the viewer role and `incidents.write` in the analyst role. Reading a
case tells a viewer nothing they could not already assemble from `alerts.read`, which they hold:
an incident is the readable form of alerts they may already read. Changing one is a judgement,
and judgements are attributable to the people whose job it is to make them.

Every mutation goes through the single `incidents.write` permission rather than a permission per
verb. A role that may move a case may also write on it; splitting them would describe a
distinction this project does not have.

### The detail is bounded, and says when it was

`GET /incidents/{id}` carries the newest 200 timeline entries with `timeline_truncated` telling
the caller whether that was all of them, plus the linked alerts in full so opening a case is one
call rather than one per alert. The whole story is reachable through
`GET /incidents/{id}/timeline`, keyset-paginated. A cap without a way past it would strand a long
case's early history behind an API that admits it is hiding something.

`allowed_transitions` is on the detail response, computed from the same table the server
enforces. It is the one derived field worth its place: without it, every client keeps its own
copy of the workflow and drifts from it.

### What this deliberately does not do

Assignment does not ship. `TimelineEntryType` has no `assigned` label, adding one means
`ALTER TYPE … ADD VALUE` — which cannot run in the transaction that uses it — plus a lockstep
change across four files, and recording an assignment as `observation` would put a label that
lies into the one table meant to be readable. It is not in the M3 deliverables. Notes cannot be
edited or deleted, for the reason the schema already gave: a note is a record of what somebody
thought at the time, and a rewritten one is a worse witness than a wrong one. Sorting by
severity does not ship, because it needs a three-element cursor `domain/pagination.py` does not
have and an index revision 0004 does not carry.

### Two things the review found, fixed here

A keyset cursor has to compare `(time, id)` as a **SQL row**, not as a Python tuple.
`(Column.a, Column.b) < (x, y)` is evaluated by CPython before SQLAlchemy ever sees it: element
0 is compared, `bool(Column == x)` is `False`, and the expression collapses to `Column.a < x` —
the id half is discarded and every row sharing the boundary instant is silently skipped. Three
queries in `incident_store.py` had this shape, one of them shipped in Chunk 15, and the
`# type: ignore[operator]` on each was suppressing exactly the mypy error that flags it. All
three now use `tuple_()`, as every sibling store already did. Ties are not hypothetical here:
correlation writes its `observation` line at the case's `window_start`, which is by construction
the `occurred_at` of the earliest `alert_fired`.

`extend` needed a closed-status guard. Correlation reads a case as open in one transaction and
extends it in another; until this chunk nothing could close a case in between, so the window was
unreachable. It is reachable now. Linking into a closed case would be permanent — `_link` flips
the alert to `correlated`, `uq_incident_alerts_alert_id` means it can never be relinked, and
neither the open queue nor a later correlation run would surface it again. `extend` now re-reads
the status under `SELECT … FOR UPDATE`, which serialises against `set_status`'s compare-and-set,
and returns zero if the case closed. The alerts stay open and the next run opens a new case
beside the closed one, which is what ADR-023 said should happen all along.

### No new migration

Revision 0004 already created every table, column, constraint, index and grant this chunk
writes through, including `SELECT, INSERT, UPDATE` on all four incident tables. The head stays
`0004_incident_tables`, which six places pin. A chunk that adds an API and needs no schema
change is the schema from the previous chunk having been right.

## Consequences

- Positive: two analysts working one case cannot both win, and the loser is told which of the
  two things went wrong — the workflow forbade it, or the case moved under them.
- Positive: every attempt to move a case, successful or refused, is attributable in a table the
  application cannot rewrite. The M3 criterion is met by construction rather than by convention.
- Positive: a case's severity, status and story are all derivable from records rather than
  believed, so an analyst reading a closed case can see why it was closed even after it has
  been reopened and closed again.
- Negative: a note's text is one round trip away from the case detail. That is the price of
  having exactly one place that bounds and validates analyst prose, and it will cost the M4
  dashboard an extra call.
- Negative: two status changes in the same microsecond order by row id, which is stable but
  arbitrary. Each API request is its own transaction with its own `now()`, so this needs two
  requests to land inside one microsecond; it is written down here rather than discovered later.
- Neutral: `IncidentDetail` gained two trailing defaulted fields, so `aegisnet incident REF`
  now prints the linked alerts and the truncation flag as well. Nothing else changed shape.
