# ADR-022 — When an event happened, and which way a DNS record is pointing

- Status: accepted
- Date: 2026-09-06
- Milestone: 2 follow-up (Chunk 14); fixes the two defects ADR-021's lab found

## Context

The isolated lab (ADR-021) put real Suricata 8.0.6 output through this pipeline for the
first time and found two things wrong with it, both recorded in `docs/evaluation.md` §9:

**L-F1.** A flow record is stamped when Suricata's flow manager emits it, which is when the
flow ended or timed out — typically seconds after the conversation. The normaliser filed
the event under that instant. The lab's beacon checked in every five seconds to within
15 ms, and the stored times said jitter 0.330 against D-004's limit of 0.15, so **D-004
could not see a real beacon at all**.

**L-F2.** Suricata 8 writes EVE DNS version 3, where a *request* record carries an `rcode`
as well as the response. D-003 read "has an rcode" as "is an answer", so on real output
every record looked like an answer: no query name was ever tallied, and every lookup was
attributed to the resolver instead of the host that asked. The lab generated thirty distinct
names carrying a sixty-character label — twenty is the threshold — and **D-003 said nothing**.

Neither was visible from generated data, because both generators had the same assumptions
inside them. `tools/gen_synthetic_eve.py` emitted `flow.start = when - age` and
`timestamp = when`, which is the relationship a real sensor reverses, and it wrote DNS in the
v2 shape where only answers carry an rcode. The labelled fixtures passed because they were
built to the detectors' reading of the schema rather than to Suricata's behaviour.

## Decision

### A flow event is filed under `flow.start`

For `event_type: flow` only, the normalised `event_time` is `flow.start` when the record
carries one that parses. Every other event type keeps its own `timestamp`, because for every
other type the timestamp *is* the moment the thing happened: an alert is stamped when the
signature matched, an http record when the transaction completed.

The emission time is not lost — the whole record is stored as the event's payload — and it
is not promoted to a column either, because nothing reads it. A schema change to carry a
field no rule uses would be cost without a reader.

`flow.start` is read best-effort: absent, empty, malformed, or naive, and the event falls
back to the record's own timestamp. A flow record with an unreadable start is still a usable
flow record, and refusing it would lose data over a field that has a sound fallback. What is
*not* best-effort is the freshness window (T-1.7): it is checked against both the record's
own timestamp and the instant the event is filed under, so a sensor whose flow start is
decades out is refused rather than quietly believed.

Deduplication is untouched *by the normalisation change*. The event hash is built from the
record's own timestamp (`domain/eve/hashing.py`), not from the normalised `event_time`, so
changing which instant an event is filed under cannot make the same line hash twice or two
lines collide. A test says so, because that is the property the whole change rests on.

The regenerated corpus is a different matter and worth saying plainly: its flow records carry
different timestamps now, so their hashes differ from the old corpus's. An operator who
ingested the previous corpus and then ingests this one gets both, because they are different
records. That is correct — they are — and it is the one visible cost of correcting data rather
than only code.

### A DNS record's direction comes from its own `type`

`dns.rcode` is promoted only when the record is a reply: `dns.type` is `answer` (EVE v2) or
`response` (EVE v3). When `type` is absent — older shapes, hand-written fixtures — the
presence of an rcode is the only signal there is, and it is used as before. A `type` nobody
recognises is treated as a question, because treating an unknown direction as an answer is
precisely the failure this is fixing.

D-003 needs no change: it asks "does this record carry an rcode" to tell a reply from a
question, and that question now has the right answer on both EVE versions.

### The generators are corrected, not worked around

`when` means "when the conversation happened" for every caller of the generators' `flow()`,
so a flow record now carries `flow.start = when` and `timestamp = when + age`. The committed
corpus and all 34 labelled fixtures were regenerated; the corpus generator's version moved to
2 and its sha256 changed.

Both also write EVE DNS v3 now — mostly, in the corpus's case, with a fifth still in v2 the
way a real fleet carries more than one sensor version. Without that, the shape that blinded
D-003 would be exercised nowhere but the lab.

Neither generator accepts a path any more: each resolves its destination under the repository
root it finds above its working directory, which is the rule the dataset import, the
evaluation harness and the capture sanitiser already follow. Tests pass a destination to the
functions instead, which is a parameter rather than something a caller can steer.

This is the part that matters for the future: the synthetic data now models the timing and the
shape of a real sensor, so the next detector written against it inherits the truth rather
than the assumption. The normalised event times are unchanged by the regeneration — `when`
was the record timestamp before and is the flow start now — which is why the T1 and T2 numbers
in `docs/evaluation.md` §8 did not move.

## Consequences

- Positive: on the committed real capture, **four of the five rules now fire** — D-001, D-002,
  D-003 and D-004 — where two did before. D-005 still abstains, correctly, because an hour of
  traffic cannot furnish the twenty-four hourly samples its baseline needs.
- Positive: the two fidelity tests that recorded the defects now hold the fixes down, against
  the same real capture, with the facts about Suricata's output unchanged.
- Positive: the generators are honest about time, so this class of defect cannot be
  re-introduced by writing another fixture.
- Negative: the corpus sha256 changed, so anything that pinned it had to move with it (the
  registry, the manifest, the §8 provenance line). That is the price of the corpus being data
  rather than a fixture, and the integrity tests caught every place it was recorded.
- Negative: a flow event is now filed *earlier* than the sensor announced it, so a batch
  ingested immediately after a capture can contain events whose time precedes the batch. The
  post-ingest sweep derives its window from the events themselves rather than from wall-clock
  time (ADR-020), so it covers them; the scheduled sweep's hour-long lookback covers the
  ordinary case. A flow longer than that lookback would be swept only by its own batch's
  sweep, which is worth knowing and is written down here rather than discovered later.
- Neutral: nothing in the API, the schema or the stored columns changed, so no migration.
