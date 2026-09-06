# ADR-033 — Deletion is a different principal

- Status: accepted
- Date: 2026-09-06
- Milestone: 6 (Chunk 25); resolves the deferral in
  [ADR-012](ADR-012-migrations-in-package-and-role-grants.md) and protects the append-only
  property [ADR-031](ADR-031-a-brief-is-append-only-and-a-failure-is-a-brief.md) and
  [ADR-032](ADR-032-the-report-changes-nothing-and-escapes-everything.md) rest on

## Context

`docs/data-model.md` has carried a retention table since Milestone 0 — events 90 days, rejects
and detector runs 30, the audit log 365, cases and briefs indefinitely — and nothing has ever
enforced it. Three separate places in the codebase say "the retention job that needs `DELETE`
arrives in a later milestone". This is that milestone.

The deferral was not laziness. Retention collides head-on with a property this project has
built three decision records on: **the runtime role cannot delete anything.** `audit_log` is
`SELECT, INSERT` because an audit trail the application can edit is not evidence (ADR-012), and
`investigation_briefs` and `brief_citations` joined it for the same reason (ADR-031). Chunk 24
then leaned on that again, arguing that auditing the report export was safe partly because
nobody can remove the row afterwards (ADR-032).

A retention policy needs somebody to be able to delete. The question is who.

## Decision

### A third role, whose only power is to remove

`aegisnet_retention` is created alongside the other two at database initialisation and receives,
from revision `0006_retention_role`:

```
GRANT SELECT, DELETE ON events, ingest_rejects, detector_runs, audit_log
GRANT SELECT          ON alert_events
```

and nothing else, anywhere. It cannot `INSERT`. It cannot `UPDATE`. It cannot touch a case, a
brief, an asset or a user.

The read on `alert_events` was not in the first version of this and the database suite is why
it is: the rule below keeps any event an alert still points at, and a role that cannot see the
links cannot express that. The prune failed outright rather than quietly running without the
exclusion — which is the right way round for a mistake that would otherwise have deleted
evidence, and is the reason the grant is written down with its justification next to it.

The alternative was granting `DELETE` on `audit_log` to the app role, which would have ended the
append-only property in exchange for a nightly job — a bad trade, and one that would have made
three earlier ADRs quietly false. Splitting the credential keeps every claim already made and
adds a small one: **no single principal in this deployment can both remove rows and write
anything.** The prune runs as the retention role; the audit row recording it is written by the
app role. Getting a deletion into the database without a trace would take two credentials.

`SELECT` is in the grant because a delete has to find its rows, and because a dry run has to
count them without removing any.

### Nothing that a case rests on is ever old enough

`alert_events.event_id` is `ON DELETE CASCADE`. Deleting an event an alert sampled therefore
does not fail — it removes the alert's evidence and leaves the alert standing with nothing
behind it. The exported report's provenance appendix would render its empty branch and nothing
would say why.

So the `events` rule excludes any event an `alert_events` row points at, regardless of age. The
number of such events is bounded by the sample size per alert, so the cost is small and known,
and it is the difference between a retention policy and a policy that erases the reasoning
behind the conclusions it keeps.

That exclusion is why this cannot be one generic query over a table name, and why each of the
four statements is written out in full.

### Every statement is a literal

A table name never reaches SQL from a variable and neither does a column name. The four `DELETE`
and four `SELECT count(*)` statements are written out and chosen from a fixed map by the
policy's own constants; a rule added without its statement raises rather than improvising one.
This is the same discipline the Sonar taint findings taught this project in Milestones 1 and 2,
applied to the one place where a formatting mistake would be irreversible.

### Batched, bounded, and allowed to leave work for tomorrow

A first run against a table nobody has pruned could be millions of rows, and a single statement
would hold locks for as long as it took. Each pass deletes at most `RETENTION_BATCH_ROWS` and a
run stops after `RETENTION_MAX_BATCHES` passes, reporting what it did not reach. Each pass is
its own transaction, so an interrupted run has deleted whole batches and nothing partial, and
the next run resumes — rows do not get younger.

### Off by default, and a dry run everywhere else

`RETENTION_ENABLED` is false. This is the only thing this project does that cannot be undone,
and a lab that has been collecting for a while should not lose its history because somebody
started the stack after pulling a release. The nightly actor is *sent* regardless and decides
for itself, so turning the policy on is one setting and a worker restart.

`make retention` prints what would go and removes nothing. `APPLY=1` is the only way past that,
and it refuses when the setting is off: a flag on one invocation should not overrule the
deployment's own decision.

### An existing database needs one command

`infra/postgres/init/01_roles.sh` runs only when PostgreSQL initialises an empty data
directory, so a deployment that predates this release will never see the new role — the
variable will be in `.env` and the role will not exist. The script is idempotent (every
`CREATE ROLE` is guarded), so `make db-roles` re-runs it against a live database, and
`bootstrap_env.py --add-missing` appends the two new variables to an existing `.env` without
touching a line already in it. Both are documented in the README rather than left for somebody
to discover from a connection error.

Adding that second mode is also what finally removed `--example` and `--out` from the script:
the new read and append went through argv-derived paths, SonarCloud rated it a security finding
on new code, and one bisection round located it. The flags had no user outside the tests, so the
answer was to stop taking a path rather than to argue about this particular one — the same
answer both generators, `eval-detectors` and the capture sanitiser reached before it.

## Consequences

- Positive: the append-only guarantee survives retention. `audit_log`, `investigation_briefs`
  and `brief_citations` are still `SELECT, INSERT` for the application, and a database test
  asserts it next to the new grants so the two cannot drift apart.
- Positive: a case stays explicable for as long as it is kept, because the events it rests on
  are excluded from the policy by construction rather than by hoping nobody runs a prune.
- Positive: the audit log now has a bound, which was the gap Chunk 24 widened by adding a read
  that writes to it.
- Negative: a third credential to manage, in `.env`, in both compose files, and in the init
  script. That is real operational weight for a lab project, and it is the price of not
  weakening the runtime role.
- Negative: the policy does nothing until somebody turns it on. A deployment that never sets
  `RETENTION_ENABLED` has exactly the unbounded growth this chunk was written to fix. The
  README says so plainly rather than implying the problem is solved by the code existing.
- Neutral: `events.event_time` is the sensor's clock, not the ingest clock, so a batch imported
  today containing week-old traffic is already a week into its ninety days. That is the honest
  reading of "how old is this data" and it is worth knowing before the first prune.
