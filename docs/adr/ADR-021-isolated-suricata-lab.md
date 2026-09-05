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

The network is `internal: true`, which is what makes Docker attach no default route;
`make lab-preflight` asks a running container to confirm it, rather than trusting the
declaration. The addresses are `203.0.113.0/24` — TEST-NET-3 — for two reasons: it is the
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

The point of the exercise. All three are recorded as passing tests over the committed
capture in `backend/tests/unit/eve/test_lab_capture_fidelity.py`, so they cannot drift, and
in `docs/evaluation.md` §9 with their numbers.

**It works.** 450 of 450 real Suricata 8.0.6 records normalised and stored with zero
rejects; a re-import reported 450 duplicates, so idempotency holds on real data; D-001 found
the sweep and D-002 found the authentication burst, on traffic nobody generated to a
threshold.

**L-F1 — flow records are stamped when they are emitted, not when they happened.** The
lab's beacon checks in every five seconds to within 20 ms. The `flow.start` values confirm
it (jitter 0.002). The record `timestamp` values, which is what the normaliser stores as
`event_time`, are the flow manager's emission times: jitter 0.33, more than twice D-004's
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

## Why the two defects are not fixed here

Both fixes change how an event is normalised, which changes `event_hash`, which changes
deduplication, the committed corpus, its manifest sha, the labelled fixtures and the pinned
metrics table in `docs/evaluation.md` §8. Landing that inside the chunk that discovered it
would mean shipping the finding and the reaction to it in one diff, with the evidence and
the fix entangled. They are recorded as defects with a named fix, a failing-in-spirit test
that currently passes, and a chunk of their own.

The honest consequence, stated in `docs/evaluation.md` §8 and §9: **the T1 and T2 tables
measure conformance to specifications on generated data, and the lab has now shown that for
D-003 and D-004 those specifications do not survive contact with real Suricata output.**

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
