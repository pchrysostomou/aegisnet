# Demo script

Three minutes, from a running stack to a case somebody can act on. Every timing below was
measured on the fresh-clone run recorded in
[`fresh-clone-transcript.txt`](fresh-clone-transcript.txt), not estimated.

**Before you start** (not part of the three minutes): `make bootstrap && make up && make migrate`.
If this machine has run AegisNet before, `make down` first — see the note in the README's
Quickstart, and the transcript for what happens if you do not.

---

## 0:00 — What this is, and what it is not

> AegisNet ingests Suricata EVE logs, runs five deterministic detectors over bounded windows,
> groups what they find into incidents, and writes the case out as a document. Everything it
> concludes is explainable: every alert stores the arithmetic that produced its severity.
>
> It is a lab project on synthetic and lab-captured data. **It makes no claim about detection
> accuracy on a real network** — `docs/evaluation.md` §8 says exactly what the numbers are and
> §9 says what a real sensor's output broke the first time it met one.

## 0:20 — One command builds the story

```bash
make demo-scenario
```

**12 seconds.** It seeds the inventory, imports a committed 303-event scenario, computes a week of
baselines so D-005 knows what normal looks like, sweeps the attack hour, and correlates.

What to point at in the output, in order:

- `alerts_created: 6, rules: 5` — five detectors ran; four of them fired.
- The per-rule rows: `D-001 success (3)`, `D-002 success (1)`, `D-003 success (0)`,
  `D-004 success (1)`, `D-005 success (1)`. **`D-003` firing zero times is a result, not a
  gap** — there is no DNS anomaly in this scenario and a rule that fires anyway is worse than
  one that does not.
- `cases_opened: 3, escalated: 1`.

## 0:50 — Three cases, and why they are three

```bash
docker compose run --rm api python -m aegisnet.cli incidents
```

| Case | Entity | Rules | Severity |
|---|---|---|---|
| `AEG-2026-0001` | `10.10.0.42` | D-001, D-002, D-004, D-005 | **5 — escalated** |
| `AEG-2026-0002` | `10.10.0.77` | D-001 | 3 |
| `AEG-2026-0003` | `10.10.0.42` | D-001 | 4 |

The point to make: **one host doing four different things is one case, and a second host scanning
in the same hour is not folded into it.** Correlation groups by entity and time, so a bystander
stays a bystander. The third case is the same host later, outside the join window — a separate
episode rather than an extension, which is the honest reading.

Read the escalation out of the case itself, not out of a slide:

```json
"severity_rationale": {
  "formula": "min(5, max(member severities) + (1 if distinct rules >= 3 else 0))",
  "distinct_rules": 4, "member_max": 5, "escalated": true, "result": 5
}
```

## 1:30 — The dashboard

Open <http://127.0.0.1:3000>, sign in as the admin created in Quickstart step 5.

- **The queue** — three cases, severity-ordered, filterable.
- **The case** — `AEG-2026-0001`: its four alerts, the timeline in the order things happened, and
  the workflow control drawn from the API's own `allowed_transitions` rather than a hardcoded list.
- Move it `new → triaging` and add a note. Two things to say while doing it: the transition is a
  compare-and-set, so two analysts deciding at once cannot both win; and every change *and every
  refused change* is written to an append-only audit log the application cannot edit.
- Type something hostile into the note — `<script>alert(1)</script>` is the honest thing to try.
  It renders as text, because the renderer parses a small fixed grammar straight into React
  elements and never produces an HTML string.

## 2:20 — The case as a document

```bash
make export REF=AEG-2026-0001 > case.md
```

**2 seconds.** Show the top of the file, then the appendix. Three things worth saying:

- **It is byte-identical across runs.** `make export REF=AEG-2026-0001 | diff - case.md` is empty.
  No clock reaches the document; every collection is sorted to a unique key.
- **Every untrusted value is escaped or fenced**, so a rule id or an analyst's note cannot become
  markup in whatever viewer opens it — and characters that change reading order are written out as
  `<U+202E>` rather than obeyed.
- **The appendix traces the evidence back to the import it came from**, and says so when it only
  sampled: "Traced from a sample of each alert's events."

## 2:50 — Close on the honest part

> The exported report opens by saying it is evidence of what the detectors saw, not proof of what
> happened. The investigation-brief feature is off by default and **no outbound API call has ever
> been made from this repository**. `THREAT_MODEL.md` §6 maps all thirty-six threats to named
> passing tests, and a test parses that table so it cannot quietly go stale.

---

## If you have four minutes rather than three

Two additions, in the order they are worth showing:

```bash
make eval          # rewrites docs/evaluation.md §8 in place; a test pins the block
make lab-preflight # asks a running lab container whether it can reach anything
```

`make eval` is the one to show a sceptic: the numbers in the document are generated, and a
hand-edited metric fails the suite rather than passing review. `make lab-preflight` prints
`default routes: none` from *inside* a container on the lab network — the isolation asked of the
running thing rather than asserted by a manifest.

## What to do if something fails on stage

- **`make demo-scenario` reports `password authentication failed`** — a database volume from an
  earlier run. `make down && make up && make migrate`, then retry. This is the one failure the
  fresh-clone reproduction actually hit.
- **The dashboard shows a sign-in loop** — the access token is fifteen minutes; sign in again.
- **A detector reports `skipped`** — the window exceeded the 200 000-event cap or the rule is
  disabled. `docker compose run --rm api python -m aegisnet.cli detector-runs` gives the reason,
  which is a better answer than a rule that silently truncated its input.
