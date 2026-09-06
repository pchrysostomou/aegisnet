# ADR-030 — The model is a witness, not an authority

- Status: accepted
- Date: 2026-09-06
- Milestone: 5 (Chunk 22); the inbound half of the boundary [ADR-029](ADR-029-nothing-leaves-that-was-not-named.md) opened

## Context

Chunk 21 decided what may leave. This chunk decides what may come back, and builds the one
piece of code in this project that talks to somebody else.

`THREAT_MODEL.md` TB-4 is blunt about what arrives: **untrusted content**. The model may be
wrong; it may have been steered by something an attacker planted upstream; it may invent a CVE
that reads exactly like a real one. It is also fluent, which is the part that makes it
dangerous — a confident paragraph is easier to act on than a number, and an analyst reading one
at 3 a.m. is the person this design has to protect.

## Decision

### It is off, and a missing key is not a problem to route around

`brief_enabled` defaults to false and `perplexity_api_key` defaults to `None`. With either
missing, `brief()` raises `BriefUnavailableError` and the caller records a failed brief. **An
incident is completely usable without one** — that is the property that lets this feature be
optional rather than load-bearing, and it is why the default is the one that sends nothing.

### Recommendations are an enum, not prose

A brief may suggest one of nine things, all of which a person does and none of which touches a
network: `investigate_host`, `review_with_asset_owner`, `check_baseline`,
`collect_more_evidence`, `correlate_with_other_cases`, `monitor`, `document_and_close`,
`escalate`, `no_action_needed`.

A model that invents an action is refused rather than approximated. This is the difference
between a tool that advises and a tool that is one integration away from acting: an incident
system whose AI output says "block 203.0.113.5" in a structured field is a system somebody will
eventually wire to a firewall.

The free text beside each recommendation is then scanned for the verbs that turn advice into an
operation — hacking back, scanning the source, automatic blocking, deleting logs, takedowns,
brute forcing. A brief containing any of them is rejected whole.

### Safety is a separate step from validation, and that was a bug first

The safety filter began as a pydantic `model_validator`. It was wrong, and the tests said so
immediately: **pydantic converts any `ValueError` raised inside a validator into a
`ValidationError`**. So "the model recommended attacking something" arrived indistinguishable
from "a field was too long", and the client could only ever have recorded `schema_rejected`.

Those two need different records and different conversations. Shape is validation and runs in
the model; policy is `enforce_safety`, runs after, and raises its own error. `admit()` does
both in order. The M5 acceptance criteria ask for `safety_rejected` specifically, and now there
is something that can produce it.

### An external claim needs a citation; an uncited one is kept and marked

Anything the model asserts that did not come from the packet — a threat actor, a campaign, a
technique — must point at an https source the brief also carries. A citation id pointing at
nothing is a **refusal**, because a dangling reference is a fabricated citation wearing a
number, and that reads as more trustworthy than no citation at all.

An external claim with no citation at all is different: it is **kept and marked
`UNVERIFIED`**, not dropped. A reader deciding what to trust is better served by seeing the
claim and its status than by a silent deletion they have no way to know happened.

### The brief cannot say anything about the case

There is no field in `InvestigationBrief` through which a model could express a severity, a
status, a verdict or a confidence. A test asserts the exact field set, because this is the
structural half of T-4.1: the brief is narrative, and no amount of successful prompt injection
gives it a channel to change what the detectors concluded.

### Everything about the call is bounded, and the key has two guards

One timeout, two retries with jittered backoff on the statuses worth retrying and none on the
ones that will not change, a response byte cap checked **before** anything parses it, a
`max_tokens` ceiling, a content-addressed cache so an unchanged case never spends a second
call, and a daily budget with a hard stop.

The API key is a `SecretStr`, travels only in a header, and appears in no log line — the client
records an exception's *type* rather than the exception, because an httpx error carries the
request and the request carries the `Authorization` header. It is also added to
`Settings.secret_values()`, so the log scrubber would catch it even if this file were wrong.
Both are asserted, because the second is what protects against the first being wrong one day.

`verify` is never mentioned in the client, and there is no setting that could disable it: T-3.6
is enforced by absence, and a test greps for it. The base URL is an allow-list of exactly one
host and must be https, so a misconfiguration cannot quietly redirect the traffic.

## Consequences

- Positive: every M5 failure mode named in the acceptance criteria — timeout, 429, 5xx,
  malformed JSON, prose instead of JSON, oversized response, uncited claim, unsafe
  recommendation — has a named reason and a test, and none of them harms the incident.
- Positive: the two dangerous cases are distinguishable. `safety_rejected` and
  `schema_rejected` are different records, which is what makes the first worth reviewing.
- Positive: nothing has been sent anywhere. The whole boundary is tested against committed
  fixtures through a mock transport, which is also the only way to assert what *would* have
  been sent.
- Negative: the safety filter is a denylist of English verbs, and a denylist of English is
  never complete. It is a second line behind the enum, which is the part that actually
  constrains the output; a test pins that ordinary advice still passes, because a filter that
  cries wolf is a filter somebody turns off.
- Negative: the daily budget is in memory, so a restart resets it and two workers each get
  their own. It guards a feature that is off by default; Chunk 23 moves it to Redis beside the
  other limits.
- Neutral: no schema change and no route yet. Storing briefs, the API and `make brief` are
  Chunk 23; the Markdown export and the panel are Chunk 24.
