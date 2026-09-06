# ADR-036 — Two bounds that live inside the application

- Status: accepted
- Date: 2026-09-06
- Milestone: 6 (Chunk 29); closes T-2.1 and T-2.6, the last two `partial` rows of
  [`THREAT_MODEL.md`](../../THREAT_MODEL.md) §6 that are about application code rather than about
  how the deployment is built. Discharges the first clause of ADR-016's deferral list

## Context

Chunk 27's coverage matrix found eight `partial` rows; Chunk 28 closed three
([ADR-035](ADR-035-three-limits-the-model-claimed-and-the-code-did-not-have.md)). Of the five
left, two were code and three are compose files, Dockerfiles and CI. This record is the two.

Both had the same shape. This project bounds what a *caller may ask for* very carefully — page
sizes, window widths, byte caps, request rates — and had almost nothing bounding what happens
once an ask gets through. A lockout of a fixed fifteen minutes is a fixed price an attacker pays
per batch of guesses. A query that gets past the page and window bounds runs until it finishes.

## Decision

### T-2.1 — the lock lengthens, and forgets

Each failure past `LOGIN_MAX_FAILURES` doubles the lock, from `LOGIN_LOCKOUT_MINUTES` (15) to a
`LOGIN_LOCKOUT_MAX_MINUTES` ceiling (60): 15, 30, 60, 60 …

**The ceiling is an hour, not a day, for a reason that has nothing to do with cryptography.**
There is no unlock command. `make create-user` and `make users` exist and nothing else touches a
user; the only code that clears a lock is a successful login. So the ceiling is also the longest
an operator can be shut out of their own deployment with no way back in, and an hour is the most
that seems fair to impose on somebody with no recourse. Raising it is one environment variable
once an `unlock-user` command exists, and writing that command is deliberately not this chunk.

**No migration.** The curve's input is "failures since the last success", which is
`users.failed_login_count`, and the decay's anchor is "when did the last escalation happen",
which is `users.locked_until` — because past the threshold every failure writes a new one. The
tempting third column is a `last_failure_at`, and it would be actively worse if derived from
`updated_at`: a role change or a password change also touches that, and a security decision must
not be silently reset by an unrelated write. Recording why there is no migration is part of the
change, because the next reader's first instinct will be a new column.

**The decay, and where it does not apply.** A lock nobody has touched for
`LOGIN_FAILURE_RESET_HOURS` (24) is forgotten: the next failure starts the count again at one and
clears the stale anchor. Clearing the anchor is load-bearing — forgiving the count while leaving
`locked_until` in the past would forgive it again on every later failure, and the account could
never escalate at all. There is deliberately *no* decay below the first lock: four failures a
year apart still lock on the fifth, which is what `SECURITY.md` already published. The decay
exists to stop the *escalation* being permanent, not to forgive the lock.

**Nothing the caller can see changes.** An escalation readable from the response would be an
oracle for which accounts exist and how hard somebody has been trying, so a test asserts the
locked path is indistinguishable from a wrong password and from an unknown account.

**The per-address half is R-9, and one number stopped serving two purposes.** Proxy headers are
not trusted, deliberately — an attacker who can set `X-Forwarded-For` can mint identities until
the per-address limit means nothing — so behind a NAT everyone shares one budget. That cannot be
fixed without a TLS-terminating proxy the deployment controls, which is out of scope, and it is
now written down as a residual risk instead of as a gap. What *was* a defect is that
`rate_limit_login_per_15min` fed both the per-address and the per-account limiter: an operator
whose office shares one address could only buy room by also widening how many guesses an attacker
gets at a single account. They are separate settings now, **at the same default**, so the split
loosens nothing and a test asserts that.

### T-2.6 — two statement budgets, and none for the migrator

A statement timeout is set as an asyncpg `server_settings` entry when the engine is built. Three
alternatives were rejected for reasons worth keeping:

- **Not `ALTER ROLE`.** A privilege belongs to a principal, which is why the grants live in
  migration 0006. A statement budget belongs to a *workload*, and here two workloads share one
  principal: the API, the four Dramatiq actors and the CLI all connect as `aegisnet_app`. Any
  value loose enough for a sweep loading 200 000 events is far too loose to bound a request, and
  any value tight enough for a request stops the worker. A role-level setting cannot close this
  gap; it can only choose which half to break.
- **Not per-session.** Stores open their own sessions, so there is no per-request chokepoint, and
  `SET LOCAL` on every transaction is a round trip for a value that never varies.
- **Not a default.** `create_engine(settings)` is gone. `create_api_engine` and
  `create_job_engine` say which budget a call site is asking for and the keyword is required,
  because a default is exactly how this gap would re-open: a new call site would inherit an
  answer instead of giving one.

The migrator asks for `statement_timeout_ms=0` **explicitly**. A migration that builds a GIST
index over a populated `events` table must never be cancelled half way, and writing the zero down
makes that a stated guarantee that a test reads back from a live connection rather than an
accident of the server default.

A cancelled statement (SQLSTATE `57014`) answers `503 service_unavailable` and not `500`. The
distinction is worth drawing because the two mean different things: a cancelled statement is a
query that asked for too much, and a narrower window or page is a sensible next step. Every other
driver error keeps the generic 500 path — delegated to explicitly rather than re-raised, so
nothing depends on middleware ordering. The engine also gains `hide_parameters=True`, the
companion to `echo=False`: it keeps untrusted bound values out of the string form of any
`DBAPIError`, which is what a timeout produces and what a log line would otherwise carry.

## Consequences

- Positive: `THREAT_MODEL.md` §6 is down to three `partial` rows, all about how the deployment is
  built rather than what the code does. M6's threat-model criterion is within one chunk.
- Positive: the database tests prove the budget against real PostgreSQL with `pg_sleep`, which is
  a statement that provably cannot finish inside the bound — so a passing test is seeing the
  timeout and not a fast machine. Removing the `connect_args` fails four of the six.
- Negative: a legitimate slow query now fails instead of finishing. 5 s is a guess informed by the
  slowest statement the API issues today (two aggregates over at most 30 days) and nothing else;
  a deployment with a much larger corpus may have to raise it, and the `503` says so in words
  rather than leaving somebody to read a stack trace.
- Negative: an analyst who mistypes their password five times now waits fifteen minutes, then
  thirty, then an hour, with no way to be let back in early. That is the cost of having no unlock
  command, and it is the reason the ceiling is where it is.
- Neutral: the login budgets are separate settings at the same default, so nothing about a fresh
  deployment behaves differently. What changed is what an operator *can* do.
