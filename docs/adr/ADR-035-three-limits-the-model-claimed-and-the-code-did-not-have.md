# ADR-035 — Three limits the model claimed and the code did not have

- Status: accepted
- Date: 2026-09-06
- Milestone: 6 (Chunk 28); closes three of the eight `partial` rows
  [ADR-034](ADR-034-the-threat-model-is-checked-by-the-suite.md) produced

## Context

Chunk 27 turned `THREAT_MODEL.md` §6 into a table a test parses, and writing the thirty-six rows
found three mitigations the document asserted and the code did not implement. None was a new
weakness; all three were gaps between a claim and its enforcement, which is the failure a coverage
matrix exists to find. This chunk closes them.

The order matters to how much confidence the result deserves: the matrix named them first, in
writing, and then the work was done — rather than the work being done and the matrix written to
describe it.

## Decision

### T-1.4 — a deadline, because no size cap is reached by a body that simply stops

Ingest bounded the request body, the line length, the line count, the nesting depth, the key
count and the spool. Every one of those is a *size*, and a client that opens a request, sends one
byte and waits reaches none of them: the byte cap is never approached, so nothing ever refuses.

`INGEST_UPLOAD_TIMEOUT_SECONDS` (120 s) wraps the body read in `asyncio.timeout`. Three details
are deliberate:

- **In the route, not a middleware.** A middleware would time every request on every route — a
  much larger feature — and could neither name the spool entry to discard nor audit in the ingest
  refusal vocabulary. The deadline covers the multipart parse as well, because `request.form()` is
  where a multipart body is actually read; a deadline inside `Spool.write` would leave a
  documented content type unbounded.
- **The partial upload is discarded.** `Spool.write` unlinks its file on any exception including
  the cancellation `asyncio.timeout` raises, which is the same path the byte cap already used.
- **`408`, not `413` or `422`.** `payload_too_large` would say the body was too big when it never
  was, and would make a stall indistinguishable from an oversized upload in both the response and
  the audit trail. The `422` envelope names the field at fault and no field is. RFC 9110 §15.5.9
  is exactly this case.

The test cannot flake, which is the reason it is worth having: the body yields one chunk and then
waits on an event nothing ever sets, so the request has exactly one way to end and a loaded runner
delays the refusal without changing it. There is no race, because the work can never win. It is
driven through `ASGITransport` rather than `TestClient`, whose `receive()` reads the body
synchronously and would block the event loop instead of yielding it.

### T-3.4 — a deployment-wide budget is not a limit on anybody in particular

`BRIEF_DAILY_BUDGET` has been real since Chunk 23, and this document has claimed *per-user and
per-incident rate limits* since the planning phase. Those did not exist. One number for the whole
deployment means one analyst can spend the day, and a loop on one case can spend it in a minute.

`BRIEF_USER_DAILY_LIMIT` (20) and `BRIEF_INCIDENT_DAILY_LIMIT` (10) reuse the existing fixed-window
limiter, over a window of 86 400 s. That is not an arbitrary number: the limiter's window index is
`int(now // window_seconds)`, so at a day it *is* the UTC day number, and the two counters turn
over at the same midnight as `aegisnet:brief:budget:<date>`. One clock, one story an operator can
hold. An hourly cap would not have closed the gap at all — an hourly N lets one analyst spend 24N.

Two decisions worth naming:

- **The case's share is spent before the analyst's.** `hit` increments whether or not it allows,
  so checking the analyst first would let one stuck browser tab on one case spend that analyst's
  whole day and lock them out of every *other* case. This way a loop costs the case its ten and
  the analyst ten of twenty. The accepted consequence is the mirror image: ten asks about one case
  in a day exhausts that case for everyone, which is what a per-incident limit *is*, and a brief
  is advisory — nothing about the case becomes unreadable.
- **They fail closed**, with login and ingest and unlike a read. Reads fail open so a cache outage
  does not lock an analyst out of their queue; these sit under a cap that is a spending cap *and*
  an exposure cap (R-2), and an unreachable counter is not a reason to send more to a third party
  than the deployment agreed to. The test breaks one limit at a time rather than both, because
  with the case limit checked first a version where it quietly failed open would still be caught
  by the user limit behind it and nothing would say so.

Enforcement is in the route handler. `enforce_limit` is the single place that turns "the limiter
raised" into a fail-open or fail-closed decision, and a service cannot import `aegisnet.api`
without breaking the layering contract — so enforcing in `BriefService` would mean a second copy
of that decision living below the port that exists to hide Redis from it.

### T-4.4 — nothing can run, and text could still read wrongly

The dashboard's renderer builds React elements and never an HTML string (ADR-027), and a real
browser asserts that nothing in a note or a brief executes. That is a claim about *running*. It
says nothing about *reading*: `U+202E` reverses the order of everything after it, so a note
recording `evil.test` can display as something reassuring while the stored bytes stay what they
were. The exported report has written those characters out as `<U+202E>` since Chunk 24. The
screen did not — the same note, two stories.

`frontend/src/lib/visible.ts` gives the dashboard the report's rule, from the same list of twenty
code points and in the same notation. They are **written out rather than stripped**, because a
case about somebody who used one has to show that they did.

Three things this taught:

- **The substitution belongs at the text leaf, after the grammar has run.** Rewriting the source
  first would let the marker it produces be parsed as something; doing it at the leaves means the
  marker cannot be parsed at all, by construction.
- **It exposed a second defect.** The block grammar matched `\s`, and JavaScript's `\s` and
  `String.trim()` both include `U+FEFF`. So a line beginning `U+FEFF` and then `> quoted` was read as a quote and the character
  was *consumed by the marker* — gone from the screen and absent from it, while the report wrote
  it out. Python's `str.strip()` does not strip format characters, which is why the backend never
  had this. Every marker now matches `[ \t]`, which is what the grammar always meant.
- **The guard is shaped like the failure.** The way this regresses is not two character lists
  drifting apart; it is a new text node that forgets the call. So the renderer's test renders every
  construct carrying all twenty characters and asserts none survives — which fails the moment an
  unwrapped text node appears. The drifting-lists failure is covered separately, by a Python test
  that compiles the TypeScript class and the report's own and compares them code point by code
  point.

The bare-text sites outside the renderer — a case's closure reason, a correlation key, a timeline
entry's detail, an asset's owner — are wrapped too. That list is *enumerated* rather than
guaranteed by construction, which is a weaker property, and it is written down here rather than
implied.

## Consequences

- Positive: three rows move from `partial` to `test`, and five remain. M6's threat-model criterion
  is met when the column holds only `test` and `accepted`.
- Positive: the two defects nobody was looking for — the `\s` grammar and the missing brief limits
  — were both found by writing down what the document claimed and checking it, which is the return
  on Chunk 27.
- Negative: `make eval`-style operator friction, in miniature. An analyst who legitimately asks
  about one case eleven times in a day is refused, and the number is a guess informed by nothing
  but judgement. It is configurable and the refusal says when to come back.
- Negative: a rendered `<U+202E>` is ambiguous with a note that literally typed those characters.
  The report accepted that trade in Chunk 24 and this inherits it; it errs toward over-reporting.
- Neutral: emoji built from zero-width joiners render as their components plus `<U+200D>`. Visibly
  wrong rather than silently wrong, and the same as the exported document.
