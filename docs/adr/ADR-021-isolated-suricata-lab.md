# ADR-021 — The isolated Suricata lab, and what it found

- Status: accepted
- Date: 2026-09-06
- Milestone: 2 (Chunk 13); resolves the deferral in ADR-009 (decision D-9)

## Context

ADR-009 moved the Suricata lab out of Milestone 1 and left a promise behind it: the lab
would arrive in Milestone 2, it would stay on an internal network with no route to the host
LAN or the internet, and **any divergence between real Suricata output and the committed
synthetic corpus would be a Milestone 2 finding**.

By Chunk 12 everything downstream of ingest existed — five detectors, a sweep, a schedule,
a metrics table — and all of it had only ever seen data this repository generated. The
synthetic corpus was written to a reading of the EVE schema. Whether that reading was right
was, at that point, an assumption in the load-bearing position.

## Decision

### The lab is three containers on a network with no way out

`infra/lab/docker-compose.lab.yml`, opt-in behind the `lab` profile, separate from the
application stack:

| Service | What it is |
|---|---|
| `target` | The only listener: HTTP on 8080, a second HTTP port for beacon check-ins, and a minimal DNS responder. The project's own runtime image, non-root. |
| `suricata` | `jasonish/suricata:8.0`, pinned by digest, sharing `target`'s network namespace so it sees that container's interface. IDS only. |
| `generator` | Six shaped conversations with `target`, and no other destination in the file. |

The network is `internal: true`, which removes the default route and drops anything that
would be forwarded off the bridge. That alone is not isolation, and finding out why is the
most useful thing the review of this chunk produced: Docker still gives the host side of the
bridge the subnet's first address, and a container reaches it over its own on-link route
with no default route involved. On this machine, a lab container could open a connection to
a service listening on `203.0.113.1` while `make lab-preflight` happily reported "no default
route". The network therefore also sets `com.docker.network.bridge.inhibit_ipv4`, which
leaves the bridge with no address at all, and the pre-flight check now proves the result
from inside a container — it derives the first address of its own subnet and fails if
anything answers there. Run against a network without the option, that check fails, which
is how it was shown to be capable of failing. The addresses are `203.0.113.0/24` — TEST-NET-3 — for two reasons: it is the
documentation space `docs/evaluation.md` §1 already reserves, and the detectors' internal
list deliberately counts documentation ranges as *external*, so the outbound rules can see
lab traffic instead of skipping it as internal-to-internal.

### One capability, added back in the open

Every service drops all capabilities. The sensor then adds back exactly `NET_RAW`, because
no capability-less process can open a packet socket. It stops there: `promisc: no` means no
interface flag is ever set, so `NET_ADMIN` is unnecessary. A test pins the list to
`["NET_RAW"]` on that one service, so widening it is a decision somebody has to make in
public rather than a diff nobody notices.

Suricata therefore runs as root inside its container, with two consequences worth stating
plainly: it can open a raw socket on the interface it shares with `target`, and it can do
nothing else — no `CAP_DAC_OVERRIDE`, no `CAP_SETUID`, no host namespace, no port, no
volume it does not own. That is a smaller privilege than the alternative, which was to hand
it `SETUID`, `SETGID` and `CHOWN` so its entrypoint could drop to its own user.

### The capture goes into a volume, not onto the host

The sensor writes into a named volume mounted at `/capture`, and `make lab-export` copies
the result out when the operator asks. Two reasons, the second discovered the hard way:

- a raw capture reaches the operator's disk deliberately, not as a side effect of a run;
- a host bind mount was tried first, and on Docker Desktop, deleting the previous run's
  files on the host leaves the mount stale often enough that the sensor intermittently
  cannot create `eve.json` at all. The run then completes, reports success, and produces
  nothing. A named volume has no such coherence problem.

The mount point is `/capture` rather than the image's own `/var/log/suricata`, because
Docker creates a mount point the image lacks as root-owned, and root without
`CAP_DAC_OVERRIDE` cannot write into a directory the image gave to another user.

### Publishing requires passing a sanitiser that can refuse

`tools/sanitize_eve.py` is a filter with a veto. It drops sensor records and records with no
`event_type`, strips every content-bearing key at any depth (payloads, packets, bodies,
headers, cookies, file names, certificate subjects, credentials, banners), bounds strings —
and then **refuses to write anything at all** when what remains still contains:

- a key that is on neither the strip list nor the published-key allowlist. A key nobody has
  classified is a key nobody has read, and the tool names it rather than guessing;
- an address outside RFC 1918/RFC 5737/loopback space, **wherever it appears** — including
  inside a list, which is where Suricata puts DNS answers, and inside a longer string such
  as a URL;
- a hostname outside the documentation domains, likewise wherever it appears, including
  inside a certificate subject or a header value;
- a URL parameter whose *name* announces a credential (`password`, `api_key`, `token`…).
  The value is unknowable; the name is enough to stop.

`--check` re-runs the refusal pass against a file **exactly as it sits on disk**, with no
stripping first, which is what makes it an assertion about the committed bytes rather than
about a repaired copy of them. Refusal rather than redaction is deliberate throughout: a
capture that saw the real internet is not a sanitising problem, it is a "stop and look at
what happened" problem.

Its output is a normal registered dataset — `samples/lab/lab-capture-01.ndjson`, with a
manifest and a `sha256` in `samples/registry.yml` — so the lab's own output enters the
system through the same door as everything else, with the same caps and the same checks.

## What the lab found

The point of the exercise, as it stood on 2026-09-06. All three are recorded as passing tests
over the committed capture in `backend/tests/unit/eve/test_lab_capture_fidelity.py`, so they
cannot drift, and in `docs/evaluation.md` §9 with their numbers. **L-F1 and L-F2 were defects
when this was written and were fixed in the next chunk ([ADR-022](ADR-022-event-time-and-dns-direction.md));
the tests that recorded them now hold the fixes.**

**It works.** 463 of 463 real Suricata 8.0.6 records normalised and stored with zero
rejects; a re-import reported 463 duplicates, so idempotency holds on real data; D-001 found
the sweep and D-002 found the authentication burst, on traffic nobody generated to a
threshold.

**L-F1 — flow records are stamped when they are emitted, not when they happened.** The
lab's beacon checks in every five seconds to within 15 ms. The `flow.start` values confirm
it (jitter 0.001). The record `timestamp` values, which is what the normaliser stores as
`event_time`, are the flow manager's emission times: jitter 0.330, more than twice D-004's
limit of 0.15. **D-004 cannot see a real beacon at all.** The synthetic corpus has the same
property — its flow records also carry an emission-style timestamp — so this was never
visible from generated data; the labelled fixtures pass because they were written with the
detector's assumption baked in.

**L-F2 — a real DNS request carries an `rcode`.** Suricata 8 writes EVE DNS version 3,
where request and response records both carry `rcode`; the generator writes version 2, where
only answers do. D-003 reads "has an rcode" as "is an answer", so on real output every
record looks like an answer: no query name is ever tallied, and attribution flips from the
host that asked to the resolver that answered. The lab generated 30 distinct names with a
60-character label — an unmistakable tunnel shape, well past the threshold of 20 — and
**D-003 said nothing.**

**L-F3 — alert metadata is a configuration choice.** An alert record carries its `flow`
counters and its `http` block only when the sensor sets `eve-log.types.alert.metadata: yes`.
The lab's first configuration had it off, and produced alerts materially thinner than the
corpus's. The lab's configuration now sets it, and a test keeps it set.

D-005 abstained, correctly: it needs 24 sampled hours of baseline and a capture is one hour
long. Exercising it needs a lab that runs on a schedule for a day, which is a separate piece
of work.

## Why the two defects were not fixed here

**Both were fixed in the next chunk: [ADR-022](ADR-022-event-time-and-dns-direction.md).**
The conclusion below held; one of its reasons turned out to be wrong, and it is worth leaving
both on the record.

Both fixes change how an event is normalised, so the chunk that made them also had to
regenerate the committed corpus, its manifest sha and the labelled fixtures. Landing that
inside the chunk that discovered the defects would have meant shipping the finding and the
reaction to it in one diff, with the evidence and the fix entangled. That was the right call.

The reason given here for the size of the change was not: this record claimed the fixes would
change `event_hash` and therefore deduplication. They did not. The hash is built from the
record's own timestamp, not from the instant an event is filed under, and the pinned §8 table
did not move either. The change was smaller than the chunk that found the defects believed —
which is an argument for measuring a blast radius rather than estimating one.

The honest consequence at the time, stated in `docs/evaluation.md` §8 and §9: **the T1 and T2
tables measure conformance to specifications on generated data.** The lab showed that for
D-003 and D-004 those specifications did not survive contact with real Suricata output; both
have since been corrected, and the tables did not change, which is the sharpest available
statement of what a synthetic corpus can and cannot tell you.

## Consequences

- Positive: the ingest path is proven against real sensor output, and the proof is a
  committed dataset anyone can re-run without Docker.
- Positive: two real defects found immediately, with executable evidence, exactly as ADR-009
  said the lab would be judged.
- Positive: the safety properties are declarations a test can read, plus one pre-flight
  command that asks the running system.
- Negative: a second compose file, a third-party sensor image, and one capability exception.
  Each is opt-in, pinned and tested, and none of it starts unless an operator asks for it.
- Negative: the lab proves nothing about a real network. Its traffic is generated by a
  script, on a network with three containers, against a target that exists to be talked to.
  T3 in `docs/evaluation.md` remains a qualitative tier and no accuracy claim rests on it.
