# ADR-023 — What makes two alerts one case

- Status: accepted
- Date: 2026-09-06
- Milestone: 3 (Chunk 15)

## Context

Five detectors produce alerts. An analyst does not work alert by alert: a scan, the failed
logins that follow it and the transfer after those are one thing that happened, and the job
of correlation is to say so.

Every way of saying so is a guess about identity. A tool that decides a scan from one host
and an upload from another are the same actor is making an inference the analyst then has to
check — and when it is wrong, it is wrong in the most expensive way, by hiding one story
inside another. `docs/delivery-plan.md` M3 fixes the shape of the answer: entity plus a
sliding time window, escalating when at least three distinct rules agree.

## Decision

### One entity, one story, and no inference beyond that

Alerts are grouped by their own `entity_type=entity_value` — `src_ip=10.10.0.42` — and by
time. Nothing else. `src_ip=10.10.0.42` and `dest_ip=10.10.0.42` are different keys, because
merging them is a judgement about direction that belongs to a person. Two entities never meet.

The cost is fragmentation: a multi-stage attack across three hosts becomes three cases. That
is the deliberate trade. A fragmented case makes an analyst do the joining, which they can;
a wrongly merged case makes them undo it, which they usually will not notice they need to.

The grouping itself (`domain/correlation.py`) is pure. It reads no clock, no database and no
configuration, so a run can be replayed from stored alerts and produce the same answer. That
is what makes "correlation is idempotent" a property rather than an intention.

### The window slides from the end, and stops at a day

An alert continues a case when it begins no more than **an hour** after the last thing in it.
Measuring from the case's end rather than its start is what lets a case grow while activity
continues, and close when it stops. A case stops growing at **24 hours** regardless, so an
incident stays something a person can read in one sitting; the next alert opens a new one.

Both are constants with reasons written beside them rather than settings, because a knob here
changes what "an incident" means, and that should be a decision somebody makes in a diff.

### Severity is derived, and escalation needs three rules

`min(5, max(member severities) + 1 if distinct rules >= 3)`. The arithmetic is stored with the
case, so a severity can always be re-derived from the alerts rather than trusted because it
was written down — the same rule the detectors follow for their own scores (ADR-018).

Three distinct rules is where a set of alerts stops reading as coincidence. Repetition is not
corroboration: the same rule firing five times about one host is one rule's opinion, and does
not escalate.

### A closed case never absorbs a new alert

A closed case is a judgement somebody made. New activity on the same entity opens a **new**
case, whose timeline names the closed one. Extending a closed case would quietly edit a
conclusion; opening a new one leaves both on the record.

Only a *recent* closure is named — inside the same join window — because a case closed last
month is not the predecessor of today's activity, and saying so would be noise.

### An alert belongs to exactly one case, and the database says so

`incident_alerts` has a UNIQUE on `alert_id`, and `incident_timeline` a UNIQUE on
`(incident_id, entry_type, alert_id)`. Both inserts are `ON CONFLICT DO NOTHING`.

This is deliberately enforced in the schema rather than in the service. A check in Python
holds for one process on a good day; a constraint holds for two correlation runs racing each
other, which is the case that would otherwise fan one case out into several. It also means
correlation never *moves* an alert: once an alert is in a case, a later run leaves it there,
because an analyst may have put it where it is.

### Case numbers come from a sequence

`AEG-2026-0001`, where the ordinal is `nextval('incident_case_seq')`. Two runs asking for
"the next one" at the same moment must not both get it, which a count would allow. The
sequence does not reset per year, so a case number identifies a case for the life of the
deployment; the year in the string is the year the case was opened.

### The workflow is data, not code

`domain/incidents.py` holds the transition table. Any open state may close, because an analyst
who has seen enough should not have to walk through the middle of the process to say so; a
closed case reopens only into `investigating`, never back to `new`, which would erase the fact
that it had been looked at; and a move to the status a case already has is refused rather than
ignored, because it is almost always a client that lost track.

The three closed states — true positive, false positive, benign — exist because *why* a case
closed is the part that is worth having later, and a single `closed` throws it away.

## Consequences

- Positive: a multi-stage scenario against one asset becomes one case with an escalated
  severity and an ordered timeline, which is M3's first acceptance criterion, tested against
  fakes and against PostgreSQL.
- Positive: idempotence is a schema property, so it survives concurrency, not just repetition.
- Positive: the grouping is a pure function anyone can read and argue with in one sitting.
- Negative: activity spread across several hosts fragments into several cases, and nothing in
  the product yet links them. That is the honest state, and the alternative was guessing.
- Negative: an hour and a day are judgement calls with no measurement behind them yet.
  `docs/evaluation.md` §8's correlation metrics — grouping precision and recall, fragmentation,
  contamination — are still empty, and they are the thing that would turn these numbers from
  reasonable into justified.
- Deferred to the next chunk: the HTTP API, the audit entries for every transition, the RBAC
  matrix for incident routes, and the timeline entries a human action produces.
