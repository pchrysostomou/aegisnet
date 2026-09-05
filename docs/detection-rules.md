# Detection rules

Status: **D-001 implemented (Milestone 2, Chunk 8); D-002 to D-005 planned.** Every rule is a pure,
versioned, parameterised function over a bounded event window (`backend/src/aegisnet/domain/detectors/`,
ADR-017). This document is the specification each implementation and each labelled fixture is checked
against; a parameter change is recorded here with the metric before and after (`docs/evaluation.md` §4).

## Shared contract

| Concern | Rule |
|---|---|
| Input | An `EventWindow`: `[start, end)` of at most 24 hours and 200 000 events, sorted by `(event_time, id)`, loaded and bounded outside the detector. `event_time` is the data's clock (T-1.7): a forged timestamp can move an event between windows, never widen one |
| Output | Zero or more `DetectionResult`s, one per `(rule, entity, window bucket)`. `dedup_key = rule_id:entity_type=entity_value:window_bucket`, where the bucket is the window start floored to the rule's `window_seconds`, so a re-sweep over the same interval produces the same key and the alert store can refuse the duplicate |
| Evidence | Derived and bounded (FR-5.3): scalars and lists of at most 50 scalars, at most 32 keys, strings of at most 128 characters, and never a key named `raw`, `line`, `raw_line`, `raw_excerpt` or `payload`. A raw log line cannot travel in evidence |
| Samples | At most 50 contributing event ids with a role (`first`, `last`, `peak`, `sample`); `event_count` carries the total |
| Signal strength | 0..1, how far past its threshold the rule went; feeds severity |
| Confidence | 0..1, how sure the rule is that the pattern is what it looks like; stored with the alert |
| Severity | `clamp(floor(base + 0.5 * (asset_criticality - 3) + 2 * (signal_strength - 0.5) + 0.5), 1, 5)`, computed when the alert is written (asset criticality needs the inventory) and stored with a rationale that reproduces it (`severity.py`, FR-5.2) |
| Purity | No I/O, no clock, no randomness; the same window in any order gives the same results, sorted by entity |
| Fixtures | Each rule has at least three positive and three negative labelled cases under `backend/tests/fixtures/labelled/<rule>/`, rendered by `tools/gen_labelled_fixtures.py` from case definitions and byte-identical on regeneration. At least one negative is the case a naive implementation gets wrong, and it is named below as the reason for a guard |

## How a sweep runs (ADR-018)

`DetectionService.sweep(start, end)` covers at most 24 hours. It syncs the registry from the code
(the operator's `enabled` flag is preserved), loads the interval's events once under the event cap,
and for each rule slices that load into buckets of the rule's `window_seconds`, aligned to the grid
`window_bucket` defines. Each bucket becomes an `EventWindow`; each result becomes an alert whose
severity is computed from the rule's base severity, the result's signal strength and the
criticality of the asset the entity resolves to (default 3 when it resolves to none). The store
refuses keys it already holds, one `detector_runs` row is written per rule (`success`, `error` with
the exception type, or `skipped` with the reason), and a rule that raises never stops the others.
Operators trigger it with `make run-detectors FROM= TO=` (sync, in the api image) or
`POST /api/v1/detections/sweeps` (queued to the worker; admins only).

## D-001 Port scan — implemented, version 1

**Behaviour detected.** One source opens flows to many distinct destination ports (vertical scan) or to
many distinct destination hosts (horizontal scan) inside a ten-minute window.

| | |
|---|---|
| Rule id / version | `D-001` / 1 |
| Base severity | 3 |
| Window | 600 s |
| Entity | `src_ip` (the scanning address) |
| Events considered | `flow` records with a source address, a destination address and a destination port. Suricata `alert` records are ignored: a scan signature firing is the IDS's opinion, this rule forms its own from the flows |
| MITRE hint | T1046 Network Service Discovery (informational only) |

**Parameters** (`PortScanParams`, per source, per window; each 2 to 100 000):

| Parameter | Default | Meaning |
|---|---|---|
| `distinct_ports` | 20 | distinct destination ports across any hosts at which the rule fires |
| `distinct_hosts` | 15 | distinct destination hosts across any ports at which the rule fires |
| `min_flows` | 20 | flows a source must have in the window before it is considered at all |

**Algorithm.** Tally per source: flows, distinct destination ports, distinct destination hosts,
distinct `(host, port)` targets, unanswered flows (`pkts_toclient` is zero or absent), first and last
event. A source fires when it has at least `min_flows` flows and reaches either threshold. Both
thresholds are inclusive.

- `signal_strength = min(1, max(ports / distinct_ports, hosts / distinct_hosts) / 3)`: 0.33 at the
  threshold, 1.0 at three times it.
- `confidence = 0.5 + 0.5 * unanswered / flows`: a scan that gets no replies is the textbook shape;
  answered probes still count but are trusted less.
- Evidence: `distinct_dest_ports`, `distinct_dest_hosts`, `distinct_targets`, `flows`,
  `unanswered_flows`, both thresholds, the first 20 destination ports and 10 destination hosts,
  `window_start`, `window_end`.
- Samples: the first and last flow plus up to 18 evenly spaced flows.

**Guards and the hard negatives behind them.**

| Guard | Hard negative that motivates it (fixture) |
|---|---|
| The unit is the distinct `(host, port)` target, never the connection: a source on a single target cannot fire however many flows it opens | `negative/backup-client-one-port`: 200 SSH connections to one host. A naive "many connections in a short window" rule flags it |
| Both thresholds are absolute counts of distinct ports and hosts, not ratios of flows | `negative/lb-health-checks`: a load balancer probing 4 backends on 3 ports every two minutes; 60 flows, 12 targets, 4 hosts, 3 ports |
| `min_flows` keeps a handful of unrelated connections from being weighed | `negative/service-discovery-within-threshold`: 8 hosts × 2 ports twice, 32 flows, well under both thresholds |
| Only `flow` records count, and only per source: high-volume traffic to one service is one target | `negative/dns-client-bursts`: 300 DNS queries to the resolver |

**Positive cases.** `vertical-40-ports` (one host, 40 ports, no replies), `horizontal-30-hosts-445`
(30 hosts, port 445, no replies), `mixed-with-noise` (25 hosts × 2 ports spread over eight minutes,
buried in 60 answered web and DNS flows from three other workstations; only the scanner may alert).
All three label `expected_min_severity: 3`, which is what the formula yields for base 3, default
criticality and a signal of 0.56 to 0.67.

**Known limitations (version 1).** A scan slower than the window (fewer than 20 targets per ten
minutes) is not detected; a distributed scan from many sources is not detected (each source is
tallied alone); a scan that spoofs its source address is attributed to the spoofed address. These
are recorded rather than patched: each would need a different rule or a longer window and its own
false-positive study.

## D-002 Auth-failure burst — planned

Repeated authentication-failure indicators from one source against one service (SSH, HTTP 401/403,
Suricata auth signatures). Hard negatives to design against: a user fat-fingering a password three
times and then succeeding; a monitoring probe with a deliberately invalid credential at a low, steady
rate.

## D-003 DNS anomaly / possible tunnelling — planned

High-entropy or over-long labels, excessive NXDOMAIN, abnormal query volume per domain. Hard
negatives: CDN and cloud hostnames with long random-looking labels; a resolver asset's legitimate
volume; DNSSEC/TXT-heavy but benign traffic.

## D-004 Periodic beaconing — planned

Low-jitter, regular-interval outbound connections to a single destination. Hard negatives: NTP,
software update checks, monitoring heartbeats. D-004 needs an allow-list of known-periodic
destinations before it can ship.

## D-005 Outbound volume anomaly — planned

Outbound bytes far above the asset's rolling baseline (`asset_baselines`, recomputed on a schedule,
never inside the detector). Hard negatives: a scheduled nightly backup that matches the baseline; a
first-time asset with no baseline, on which the rule must abstain rather than alert.
