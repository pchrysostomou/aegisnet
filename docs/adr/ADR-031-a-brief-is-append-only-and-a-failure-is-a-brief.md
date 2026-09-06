# ADR-031 — A brief is append-only, and a failure is a brief

- Status: accepted
- Date: 2026-09-06
- Milestone: 5 (Chunk 23); joins [ADR-029](ADR-029-nothing-leaves-that-was-not-named.md) and [ADR-030](ADR-030-the-model-is-a-witness-not-an-authority.md) to a case

## Context

Chunk 21 decided what may leave. Chunk 22 decided what may come back. Neither was wired to
anything: there was no way to ask for a brief and nowhere to keep one.

This chunk connects them, which means deciding what a brief *is* once it exists. Two questions
turn out to matter more than the plumbing: whether a stored brief can change, and what happens
when the call does not work.

## Decision

### Append-only, in the grant

`investigation_briefs` and `brief_citations` join `audit_log` as the only tables where the
runtime role holds `SELECT, INSERT` and nothing else. No `UPDATE`, no `DELETE`, enforced by
PostgreSQL rather than by convention, and a test proves all four statements are refused.

The reason is what a brief is *for*. It records what a model said at a moment, next to
`packet_hash` — the exact question it was asked. A brief that can be edited afterwards is
evidence of nothing, and the same argument that made the audit log append-only in Chunk 2
applies here without modification.

Versioning follows. Asking again writes v2 rather than replacing v1, so an analyst can see that
the first answer was refused, or came from the offline fixture, or said something different.
Versions are allocated inside the writing transaction from the case's own maximum, and the
`UNIQUE (incident_id, version)` is what makes that safe: two requests racing for "the next one"
cannot both get it, and the loser fails rather than overwriting.

### A failure is a stored brief, and the route answers 201

Every way the call can go wrong — disabled, unconfigured, out of budget, a 503, a malformed
answer, a safety rejection — ends as a row with `status = failed` and a short reason. The route
answers `201`, not `502`.

This is deliberate and it is the opposite of what an HTTP purist would do. The request
succeeded: the operator asked, the system tried, and the outcome is recorded. Returning an
error would throw away the one fact worth keeping — that at 03:10 somebody asked and the API
was down — and would make a missing brief indistinguishable from one nobody requested.

Two database constraints keep those rows honest: a `complete` brief must have a summary, and a
`failed` one must have a reason. Neither state can be stored as the other.

### The offline brief, and why it is a different `source`

A checkout of this repository has no API key. That is the normal state, and a reviewer should
still be able to see what the feature does end to end.

So when the feature is *off or unconfigured* — and only then — a committed brief in
`samples/briefs/offline-brief.json` is served instead, stored with
`source = offline_fixture`. Never `perplexity`. Nothing in the API, the CLI or the dashboard may
present it as something a model said, and the enum is what makes that a fact rather than a
promise.

It passes exactly the same admission a real answer does — schema, https citations, safety
filter — because a fixture that could not be admitted would be a fixture that lies about what
the feature does. A test asserts that by running it through `admit()`.

A real failure is *not* replaced by the fixture. `http_503` means the API answered badly, and
quietly substituting a canned answer there would be the worst behaviour available: an analyst
reading a brief that looks real and was written by nobody.

### A viewer reads a brief; an analyst asks for one

`briefs.read` sits with the viewer, because a brief is a narrative about alerts they may
already read. `briefs.generate` sits with the analyst, because asking spends money and sends an
evidence packet outside the deployment. Those are decisions, not lookups.

### The brief appends to the case and cannot touch it

Generating writes one `brief_generated` timeline line and one `brief.generated` audit row. The
audit detail carries the version, the status, the source and the **packet hash** — which
question was asked — and never the packet or the answer. The words live in the brief, which
nothing may rewrite.

A test asserts the case is byte-identical before and after: severity, status, title, rule count
and the linked alerts. That is T-4.1's narrative-only property, checked at the seam rather than
only at the type.

The line it appends is *not* evidence, and the packet leaves it out. This was not obvious until
the feature ran: generating a brief on the stack, then generating another, produced two different
packet hashes, because the first brief's own timeline line had become part of the second
question. Two things were wrong with that. The content-addressed cache could never hit on the
case it exists for — an analyst asking twice about an incident nothing has changed — and the
model was being handed the note that somebody had asked it to explain the incident. Entries whose
subject is the tool rather than the network (`brief_generated`, `report_exported`) are excluded.

## Consequences

- Positive: a brief is evidence. What it said, what was asked, who asked, when, and whether it
  was the real thing or the committed fixture — all of it immutable at the database level.
- Positive: every failure mode M5 names is visible to an analyst rather than swallowed. "The
  API was down" is a row.
- Positive: the feature can be reviewed, demonstrated and screenshotted without a key and
  without sending anything anywhere, which is how most people will meet it.
- Negative: `201` for a failed brief will surprise somebody reading the API log. It is
  documented in `docs/api-milestone-5.md` and the body says `"status": "failed"` in the first
  field a reader looks at.
- Negative: append-only means a brief containing something regrettable cannot be edited out —
  only superseded by a new version. That is the same trade the audit log makes, and the safety
  filter and the redaction boundary are what keep the regrettable content out in the first
  place.
- Neutral: the RBAC matrix test now matches routes through the router's own regex rather than
  by substituting placeholder names. The old helper could not represent a route with two path
  parameters and reported "no such route" when one appeared — the wrong failure for a test
  whose job is to notice a route with no permission.
