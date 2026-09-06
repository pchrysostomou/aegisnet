# ADR-029 — Nothing leaves that was not named

- Status: accepted
- Date: 2026-09-06
- Milestone: 5 (Chunk 21); the outbound half of TB-3, built before any client exists

## Context

Milestone 5 adds the first thing this project has ever done that reaches outside the
deployment: an investigation brief written by Perplexity. `THREAT_MODEL.md` calls TB-3 "the
highest-consequence boundary" and says, plainly, to **assume anything sent may be retained**.

Everything AegisNet holds came from somebody's network. The events are packet metadata; the
alerts quote DNS names and HTTP hosts an attacker chose; the assets are a map of a real estate;
the notes are what an analyst typed while investigating. Sending a case to a third party means
deciding, field by field, which of that is worth a better brief and which is somebody's
infrastructure.

That decision is a design problem, not a filtering problem, and it is worth making before any
code exists that could make a request. So this chunk ships the boundary and **no client**.
Nothing in it can perform I/O; there is nothing to configure, and no key would do anything.

## Decision

### An allow-list, with default-deny recorded

`CaseEvidencePacket` is built field by field from typed values in `domain/redaction/packet.py`.
There is no code path that serialises an ORM row, an `AlertRecord`, or a raw payload — the
builder takes plain dictionaries, so a caller has to *name* what it is passing rather than hand
something over wholesale.

Every evidence key is classified: numeric, address-shaped, a closed vocabulary, a timestamp, or
explicitly dropped. **A key that is none of those is dropped and the packet says so**, in
`dropped_fields`, with the reason. A detector that starts emitting something new therefore
sends nothing new until somebody classifies it, and a reviewer can see what was withheld
instead of inferring it from an absence.

### What actually goes out is arithmetic

Forty distinct ports. A mean interval of sixty seconds with 1.6 % jitter. Four hundred
megabytes against a p95 of six. That is what a brief reasons from, it describes no
infrastructure, and — the structural answer to T-4.1 — **it is not prose, so it cannot carry an
instruction to a model.**

The few strings sent are one of three kinds: a rule id from a vocabulary this project owns, a
pseudonym, or a short value from a small allow-listed set that has been scanned and capped.

### Addresses and names become stable tokens

`asset-A` for the entity the case is about; `int-1`, `ext-1`, `domain-1` for everything else,
allocated in order of first appearance. The token carries the one fact that matters for
reasoning — which side of the perimeter it is on — and no topology. The mapping stays local so
an analyst can resolve a token; it is never sent.

Tokens are deterministic, so the same case produces the same bytes. That is what lets a content
hash key a response cache and two briefs be compared.

### A denylist behind the allow-list, and why both

The scanner in `scanner.py` looks for emails, AWS key ids, private key blocks, JWTs, bearer
tokens, credential assignments, provider tokens and base64 blobs. It is the *second* line: the
allow-list already means almost nothing textual is sent. It exists for the case where an
allow-listed field turns out to carry something it should not, and it is deliberately eager — a
false positive costs a dropped field and a recorded reason, a false negative costs a secret
sent to somebody who may retain it.

It records *which rule* matched and never the matched text, because writing the secret into the
log is the thing it exists to prevent.

### The canary suite found a leak on its first run, which is the argument for it

`tests/security/test_redaction.py` poisons every field with the shapes the threat model names
and asserts against the **serialised body** — the bytes that would leave, not the object.

Its first run failed, on a case I had not considered. `correlation_service` writes timeline
summaries like `D-001 fired on src_ip 10.10.0.42`. Those are written by this project, not by a
sensor, so the denylist had no objection to them — and they quote the entity. The address would
have gone out inside an ordinary English sentence while every structured field around it was
carefully tokenised.

The fix is that the pseudonymiser now *reads* sentences too: `scrub()` substitutes every address
and hostname in a summary with its token, so the line stays readable and carries nothing.
`D-001 fired on src_ip asset-A` is exactly as useful to a model and says nothing about a
network. A test pins it, and names why.

### Everything is bounded, and truncation is loud

24 kB serialised, twelve alerts, twenty-four evidence keys, eight items per list, twenty
timeline lines, two hundred characters of free text. When the byte cap bites, whole alerts are
dropped from the end and `packet_truncated` is set with the reason recorded (T-3.5). A packet
that quietly got smaller would produce a brief that silently described less than the analyst
believed it did.

## Consequences

- Positive: the highest-consequence boundary is proven before anything can cross it. There is
  no client, no configuration and no key in this chunk — a reviewer can read what would be sent
  without trusting that a later chunk got the filtering right.
- Positive: a leak was found by the suite rather than by a reviewer, and it was one that neither
  the allow-list nor the denylist would have caught on its own. It is written down above.
- Positive: because the payload is arithmetic rather than prose, T-4.1's indirect prompt
  injection has a structural answer and not a mitigating one — the attacker's text never
  reaches the model.
- Negative: a brief will be less specific than one written from raw data. It cannot name the
  domain a host beaconed to, only that there was one, that it was external, and how regular the
  interval was. That is the trade being made deliberately, and an analyst has the real values
  on their own screen.
- Negative: the allow-list needs maintaining. A new detector's evidence keys are silently
  unhelpful until classified — visibly so, in `dropped_fields`, which is the failure mode worth
  having.
- Neutral: no schema change, no configuration, no new dependency. `domain/redaction/` is pure
  and the import contracts hold.
