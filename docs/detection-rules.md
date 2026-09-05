# Detection rules

Status: **D-001, D-002 and D-003 implemented (Milestone 2, Chunks 8 and 10); D-004 and D-005 planned.** Every rule is a pure,
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

## D-002 Auth-failure burst — implemented, version 1

**Behaviour detected.** One source produces many authentication-failure indicators, and they come
as a burst rather than a trickle.

| | |
|---|---|
| Rule id / version | `D-002` / 1 |
| Base severity | 3 |
| Window | 600 s |
| Entity | `src_ip` (the source of the failures) |
| Events considered | Suricata `alert` records whose signature or category contains one of the configured patterns, matched case-insensitively (`brute`, `login fail`, `authentication fail`, `auth fail`, `invalid user`, `failed password`, `password guess`, `privilege gain`). Suricata is the sensor of record for auth failures in Milestone 2: EVE does not carry HTTP status codes or SSH outcomes as promoted fields |
| MITRE hint | T1110 Brute Force (informational only) |

**Parameters** (`AuthBurstParams`):

| Parameter | Default | Meaning |
|---|---|---|
| `failures` | 10 | indicators from one source in the window (2 to 100 000) |
| `burst_seconds` | 120 | the densest span of this length must hold all `failures` (1 to 3600) |
| `signature_patterns` | the eight above | lower-cased substrings, 1 to 32 entries of at most 64 characters |

**Algorithm.** Tally matching alerts per source in time order. A source fires when it has at least
`failures` indicators **and** the densest `burst_seconds` span among them holds at least
`failures` (a two-pointer sweep over the sorted times).

- `signal_strength = min(1, max_burst / failures / 3)`.
- `confidence = 0.5 + 0.5 * max_burst / failures_in_window`: all failures inside one burst is the
  textbook shape; failures spread across the window are trusted less.
- Evidence: `failures`, `max_burst`, `burst_seconds`, `threshold`, `distinct_targets`, up to ten
  `sample_targets` (`host:port`), up to ten `signature_ids`, up to five `sample_categories`
  (64 characters each), `window_start`, `window_end`. Signature *names* are never copied into
  evidence: they are sensor text.
- Samples: the first and last indicator plus up to 18 evenly spaced ones.

**Guards and the hard negatives behind them.**

| Guard | Hard negative that motivates it (fixture) |
|---|---|
| The densest `burst_seconds` span must hold the whole threshold, not just the window | `negative/monitoring-probe-steady`: a probe with an invalid credential once a minute reaches ten failures in ten minutes, the threshold count, but never more than three in any two-minute span. A rule that counts the window alone flags it |
| The count is absolute | `negative/fat-finger-three-then-success`: three failures, then a normal session; `negative/eight-failures-under-threshold`: a real burst, under the count |
| Only alerts whose text reads like an auth failure count | `negative/unrelated-alerts-volume`: 100 informational alerts from one source |

**Positive cases.** `ssh-brute-200-in-90s`, `http-login-failures-60`, `spray-two-services-with-noise`
(12 SSH and 12 RDP failures inside a minute from one source, among 70 unrelated records from other
hosts; the targets are aggregated per source so a spray is one alert, not two). All label
`expected_min_severity: 3`.

**Known limitations (version 1).** The rule sees what Suricata's ruleset labels; a service whose
failures produce no signature is invisible to it. A slow attack under one failure per twelve
seconds never bursts. Distributed attempts from many sources against one account are not
correlated (each source is tallied alone; M3 correlation may group them by target).

## D-003 DNS anomaly / possible tunnelling — implemented, version 1

**Behaviour detected.** Per querying client, one of three shapes: many distinct high-entropy names
under one base domain (the tunnelling shape), an NXDOMAIN storm by count and ratio, or a stream of
over-long labels.

| | |
|---|---|
| Rule id / version | `D-003` / 1 |
| Base severity | 3 |
| Window | 600 s |
| Entity | `src_ip` (the client). Query records are attributed to their source; answer records, the ones carrying an `rcode`, travel resolver → client and are attributed to their destination |
| Events considered | `dns` records. Distinct names are counted from query records so a query/answer pair is one name; NXDOMAIN is counted from answer records |
| MITRE hint | T1071.004 Application Layer Protocol: DNS (informational only) |

**Parameters** (`DnsAnomalyParams`):

| Parameter | Default | Meaning |
|---|---|---|
| `unique_subdomains` | 50 | distinct names under one base domain from one client at which the tunnel signal fires, provided at least half of them look random |
| `entropy_threshold` | 3.5 | bits per character of the longest subdomain label (at least 16 characters long) before a name counts as random |
| `long_label_chars` | 40 | a label of this length or more makes a name over-long |
| `long_queries` | 20 | distinct over-long names at which the long-label signal fires |
| `nxdomain_failures` | 50 | NXDOMAIN answers at which the storm signal may fire |
| `nxdomain_ratio` | 0.5 | share of the client's answers that must be NXDOMAIN |
| `allowed_suffixes` | 19 CDN, cloud and reverse-lookup suffixes | names under them never feed the tunnel or long-label signals |

**Algorithm.** Per client: the set of distinct names, the names grouped by base domain (the last
two labels), the count of query records, of answers and of NXDOMAIN answers. Signals:

- `tunnel`: a non-allow-listed base domain with at least `unique_subdomains` names of which at
  least half have a longest subdomain label of 16 or more characters and entropy at or above the
  threshold. Ratio = names / `unique_subdomains`.
- `nxdomain`: at least `nxdomain_failures` NXDOMAIN answers **and** NXDOMAIN share at or above
  `nxdomain_ratio`. Ratio = NXDOMAIN / `nxdomain_failures`.
- `long_labels`: at least `long_queries` distinct non-allow-listed names carrying a label of
  `long_label_chars` or more. Ratio = count / `long_queries`.

`signal_strength = min(1, max(ratios) / 3)`; `confidence = 0.6, 0.8, 1.0` for one, two or three
signals. Evidence: `signals`, `distinct_names`, `query_records`, `answers`, `nxdomain_answers`,
`nxdomain_ratio`, `top_domain` (the non-allow-listed base domain with most names, 128 characters
at most), `top_domain_names`, `top_domain_suspicious`, `long_names`, the three thresholds,
`window_start`, `window_end`. Query names are never copied into evidence.

**Guards and the hard negatives behind them.**

| Guard | Hard negative that motivates it (fixture) |
|---|---|
| The tunnel signal needs at least half of a domain's names to be long, high-entropy labels, not just many of them | `negative/resolver-high-volume`: a resolver forwarding 400 queries for 150 hosts of one organisation (`svc001` … `svc149`). 150 distinct subdomains would trip a unique-subdomain count on its own |
| CDN and cloud suffixes are allow-listed for the tunnel and long-label signals | `negative/cdn-cloud-hostnames`: 120 queries cycling through eight random-looking CDN and cloud hostnames |
| The storm signal needs both a count and a share; volume alone never fires | `negative/resolver-high-volume` again (5 % NXDOMAIN over 400 answers); `negative/dnssec-txt-heavy`: 100 DMARC, DKIM, DNSKEY and DS lookups, TXT-heavy but low entropy and never NXDOMAIN |

**Positive cases.** `tunnel-random-subdomains-txt` (300 distinct 40-hex-character labels under one
domain; the tunnel and long-label signals both fire), `nxdomain-storm-dga` (120 random domains,
110 NXDOMAIN), `long-labels-c2` (40 distinct 48-character labels under one domain). All label
`expected_min_severity: 3`.

**Known limitations (version 1).** The base domain is the last two labels, so `co.uk`-style
suffixes group as one domain; the allow-list is static; a tunnel that spreads its names over many
domains or keeps labels short and low-entropy is not detected by the tunnel signal (the storm and
long-label signals may still fire); a resolver asset that forwards a real tunnel is attributed to
the resolver, which is correct for the entity but hides the origin behind it.

## D-004 Periodic beaconing — planned

Low-jitter, regular-interval outbound connections to a single destination. Hard negatives: NTP,
software update checks, monitoring heartbeats. D-004 needs an allow-list of known-periodic
destinations before it can ship.

## D-005 Outbound volume anomaly — planned

Outbound bytes far above the asset's rolling baseline (`asset_baselines`, recomputed on a schedule,
never inside the detector). Hard negatives: a scheduled nightly backup that matches the baseline; a
first-time asset with no baseline, on which the rule must abstain rather than alert.
