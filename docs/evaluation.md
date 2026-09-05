# AegisNet — Safe Local Evaluation Plan

Status: **Plan only. No results yet — every results table below is a placeholder and must not be read as an
outcome.** Results are populated by `make eval` from M2 onward. At the Milestone 1 gate (2026-09-05) no detector
exists, so detector accuracy is **unmeasured** and AegisNet makes no claim about it.
Last updated: 2026-09-05

---

## 1. Safety rules for evaluation

Non-negotiable. Any evaluation run that violates one of these is invalid.

1. **No traffic leaves the host.** The lab compose file uses a Docker network with `internal: true` and no
   default route. Verified before each lab run by `docs/evaluation.md §7` checklist step E-0.
2. **No third-party systems are touched.** No scanning, probing, or connecting to any address outside the lab
   subnet or loopback. "Scan-like" behaviour exists only as *synthetic EVE records* or as lab-internal traffic
   between containers the operator owns.
3. **Primary corpus is synthetic and committed.** `tools/gen_synthetic_eve.py` is seeded and deterministic, so
   the corpus is reproducible from source with no downloads and no real capture data.
4. **No real capture data in the repo.** Only RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) and
   RFC 1918 addresses, and `example.com`/`example.test` domains.
5. **Public datasets are optional, offline, and gitignored.** Licence and required citations are recorded per
   ingest batch. CIC-IDS2017 requires citing its source paper
   ([Canadian Institute for Cybersecurity](https://www.unb.ca/cic/datasets/ids-2017.html)); UNSW-NB15 grants free
   academic use in perpetuity, requires author agreement for commercial use, and requires citing five listed
   papers ([UNSW Canberra](https://research.unsw.edu.au/projects/unsw-nb15-dataset)).
6. **No Perplexity calls during detector evaluation.** Detection metrics must be independent of the AI layer.

## 2. Three-tier corpus

| Tier | Source | Purpose | Committed? |
|---|---|---|---|
| **T1 — Synthetic unit fixtures** | EVE JSON in `backend/tests/fixtures/labelled/<rule>/` with `labels.yml`, rendered from hand-specified case definitions by `tools/gen_labelled_fixtures.py` (seeded; a test pins the committed files to the generator) | Per-detector correctness: precision/recall against exact ground truth | Yes |
| **T2 — Synthetic scenario corpus** | `tools/gen_synthetic_eve.py --scenario ...` — multi-hour, multi-asset, with injected benign noise | End-to-end pipeline, correlation quality, false-positive rate under noise | Yes (generator + manifest; corpus regenerated deterministically) |
| **T3 — Isolated lab capture** | `infra/lab/` containers generating benign traffic plus operator-authorised scripted behaviour, observed by Suricata | Realism check: does the pipeline survive real EVE output | No (operator-local; a small sanitized excerpt may be committed) |

T3 is a *qualitative* tier. Headline metrics come from T1 and T2, where ground truth is exact.

## 3. Ground-truth labelling

Every fixture directory contains:

```yaml
# tests/fixtures/labelled/D-004-beaconing/positive/low-jitter-60s/labels.yml
case_id: D-004-pos-low-jitter-60s
rule_id: D-004
expected: detection
expected_entity: { type: asset, value: lab-workstation-03 }
expected_min_severity: 3
window: { start: "2026-01-01T00:00:00Z", end: "2026-01-01T02:00:00Z" }
notes: "60s interval, 4% jitter, 120 connections to a single external endpoint"
```

Negative cases use `expected: no_detection` and are chosen to be **adversarially benign** — the near-miss cases
that a naive threshold would flag:

| Rule | Hard negatives that must NOT alert |
|---|---|
| D-001 port scan | Load balancer health checks across a few ports; a backup client opening many *connections* to one port; legitimate service discovery within threshold |
| D-002 auth burst | A user fat-fingering a password 3 times then succeeding; a monitoring probe with a deliberately invalid credential at a low, steady rate |
| D-003 DNS anomaly | CDN and cloud hostnames with long random-looking labels; legitimate high-volume DNS from a resolver asset; DNSSEC/TXT-heavy but benign traffic |
| D-004 beaconing | NTP, software update checks, and monitoring heartbeats — periodic *and legitimate*; these are the reason D-004 needs an allow-list of known-periodic destinations |
| D-005 volume anomaly | A scheduled nightly backup that is large but matches the asset's baseline; a first-time asset with no baseline (must abstain, not alert) |

Rule: at least one hard negative per detector must be a case that a naive implementation gets wrong, and that
case must be named in `docs/detection-rules.md` as the reason for a specific guard.

## 4. Metrics

Per detector, computed over T1 + T2:

- **Precision** = TP / (TP + FP), **Recall** = TP / (TP + FN), **F1**.
- **Alerts per 10k events** on a pure-benign T2 corpus — the practical false-positive-rate proxy.
- **Detection latency** = alert `created_at` − scenario ground-truth onset (sweep-bounded).
- **Severity agreement** — does the computed severity fall in the labelled expected band.

Correlation metrics:

- **Grouping precision/recall** against labelled scenario ground truth (which alerts *should* share a case).
- **Case fragmentation** = incidents produced ÷ incidents expected (target 1.0; >1 means over-splitting).
- **Case contamination** = share of incidents containing alerts from unrelated scenarios (target 0).

Targets (to be met or explicitly explained in the results section):

| Metric | Target |
|---|---|
| Per-detector recall on T1 positives | 1.00 (fixtures are the spec) |
| Per-detector precision on T1+T2 | ≥ 0.90 |
| Alerts per 10k benign events | ≤ 5 per detector |
| Correlation fragmentation | 1.0 ± 0.2 |
| Case contamination | 0 |

Missing a target is an acceptable outcome **if** it is reported with the reason and a tuning note. Silently
adjusting thresholds until the numbers look good is not — parameter changes are recorded in
`docs/detection-rules.md` with the metric before and after.

## 5. AI brief evaluation (qualitative + hard safety gates)

Detection metrics are quantitative; brief quality is not. Evaluation is therefore a rubric plus automated gates.

**Hard automated gates (must pass, part of `make test-security`):**

| Gate | Assertion |
|---|---|
| G-1 Redaction | Canary-poisoned events produce a request body containing zero canary strings |
| G-2 Size | Serialized packet ≤ configured cap; truncation flagged |
| G-3 Schema | Non-conforming responses are rejected, never partially stored |
| G-4 Citations | Uncited external claims stored and rendered `UNVERIFIED` |
| G-5 Safety vocabulary | Responses recommending offensive or automated actions are `safety_rejected` |
| G-6 Non-authority | Brief generation cannot modify any alert or incident field |
| G-7 Injection resistance | Injection corpus in DNS/HTTP fields does not change the brief's factual sections in a way that contradicts the evidence, and never changes detection state |
| G-8 Log hygiene | No API key, no packet content in any log record |

**Manual rubric (1–5, scored on 5 fixed scenarios, recorded in the results section):**
faithfulness to supplied evidence · no invented IOCs · hypotheses genuinely distinct and testable · evidence gaps
useful and specific · triage steps read-only and actionable · containment recommendations clearly advisory ·
limitations honest.

Any brief scoring ≤2 on faithfulness is a **defect**, not a tuning note.

## 6. Reproducibility requirements

Every published number must be accompanied by: the command, the corpus commit sha, the detector `rule_version`s,
and the generator seed. `tools/eval_report.py` emits these automatically into the results section, so hand-edited
metrics are detectable in review.

```
make eval            # T1 + T2, writes results into docs/evaluation.md
make eval-lab        # T3 qualitative run, requires the opt-in lab stack
make test-security   # gates G-1..G-8
```

## 7. Lab-run pre-flight checklist (T3)

- [ ] **E-0** `docker network inspect aegisnet_lab` confirms `"Internal": true` and no gateway route.
- [ ] E-1 Only containers created by `infra/lab/` are on that network.
- [ ] E-2 Traffic generators target lab container names/addresses only; the generator scripts contain no
      externally routable address and a test asserts this.
- [ ] E-3 The operator confirms in writing (commit message) that all lab systems are theirs.
- [ ] E-4 Suricata runs in IDS mode only; no inline/IPS configuration, no drop rules.
- [ ] E-5 After the run, `eve.json` is reviewed and sanitized before any excerpt is committed.

## 8. Results

> **Empty by design.** Populated from M2 onward by `make eval`. Until then, AegisNet makes **no** claims about
> detector accuracy.

### Per-detector metrics
| Rule | Corpus | TP | FP | FN | Precision | Recall | F1 | Alerts/10k benign |
|---|---|---|---|---|---|---|---|---|
| D-001 | — | — | — | — | — | — | — | — |
| D-002 | — | — | — | — | — | — | — | — |
| D-003 | — | — | — | — | — | — | — | — |
| D-004 | — | — | — | — | — | — | — | — |
| D-005 | — | — | — | — | — | — | — | — |

### Correlation metrics
| Metric | Value |
|---|---|
| Grouping precision / recall | — |
| Case fragmentation | — |
| Case contamination | — |

### AI brief rubric
| Scenario | Faithfulness | No invented IOCs | Hypothesis quality | Gap usefulness | Triage safety | Limitations honesty |
|---|---|---|---|---|---|---|
| — | — | — | — | — | — | — |

### Known limitations (to be expanded with real results)
- Heuristic detectors will miss techniques not represented in the corpus.
- Synthetic corpora are cleaner than real networks; T2 false-positive rates are optimistic.
- Correlation is entity+time based, so multi-hop activity across unrelated entities will fragment into
  separate cases.
- Citation checking verifies that a URL exists and resolves, not that it supports the claim.
