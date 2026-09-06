# The isolated Suricata lab

Three containers on a Docker network with no route anywhere. One of them talks to another
in six deliberate shapes; Suricata watches the conversation and writes EVE JSON; a
sanitiser turns a slice of that into something safe to commit. That is the whole lab.

It exists to answer one question the synthetic corpus cannot: **does real Suricata output
survive this project's ingest path, and do the detectors read it the way they read
generated data?** The answer, from the first run, is in [`docs/evaluation.md`](../../docs/evaluation.md) §9.

The decision and its reasoning are [ADR-021](../../docs/adr/ADR-021-isolated-suricata-lab.md);
the safety rules it obeys are [`docs/evaluation.md`](../../docs/evaluation.md) §1 and the
L-0 … L-5 pre-flight checklist in §7.

---

## What is safe about it, concretely

| Property | How it is guaranteed |
|---|---|
| Nothing reaches the internet, the host, another Docker network, or another container's published port | Two things, and the second is the one that is easy to miss. `internal: true` removes the default route and drops anything that would be forwarded off the bridge. On its own that is **not** enough: Docker normally puts the subnet's first address on the host side of the bridge, and a container reaches that with no default route at all — on this machine, before the fix, a lab container could open a connection to a service listening on `203.0.113.1`. The network therefore also sets `com.docker.network.bridge.inhibit_ipv4`, so the bridge has no address to talk to. `make lab-preflight` proves the result instead of trusting it: it runs inside a lab container, derives the first address of its own subnet, and fails the run if anything answers there or outside. |
| Nothing reaches a system the operator does not own | The generator has exactly one destination, the `target` container, resolved by compose service name. A test walks every file here and fails on any address outside documentation and private space. |
| Suricata never blocks anything | IDS only: no inline transport, no `copy-mode`, no IPS flags, and every rule starts with `alert`. Tests assert each of those. |
| No scanning or exploitation tooling exists here | A test fails if any file mentions one, by name, from a list. |
| The raw capture never reaches git | `infra/lab/out/` is ignored twice over, and the repository ignores `eve*.json` and `*.pcap` everywhere. |
| Only a reviewed excerpt is published | `tools/sanitize_eve.py` strips content-bearing fields and then **refuses** to write anything at all if what remains holds an unclassified key, an address or name outside documentation space anywhere (inside a list, inside a URL), or a URL parameter whose name announces a credential. It accepts no path: it reads and writes fixed names under the checkout it finds. |

The one hardening exception in the whole repository lives here: the sensor adds
`CAP_NET_RAW` back after dropping every capability, because no capability-less process can
open a packet socket. It stops there — `promisc: no` means no interface flag is ever set,
so `CAP_NET_ADMIN` is not needed, and a test pins the list to exactly `["NET_RAW"]`.

---

## The run

```bash
make lab-capture        # clean, pre-flight, sensor up, traffic, flush  -> infra/lab/out/eve.json
make lab-soak HOURS=24  # the same, held open for a day, so D-005 gets 24 sampled hours (#12)
make lab-sanitize       # L-5: strip and verify                        -> samples/lab/lab-capture-01.ndjson
make lab-down           # stop everything and remove the lab network
```

`make lab-capture` takes about two minutes, most of it the beaconing scenario waiting out
its twelve five-second intervals. To watch a single shape instead:

```bash
make lab-up
make lab-traffic SCENARIOS=sweep,dns
make lab-down
```

Then, with the application stack running (`make up && make migrate`):

```bash
make eval-lab           # T3: ingest the sanitised capture, sweep it, print what fired
```

### Before you publish anything from a run

Work through the checklist in [`docs/evaluation.md`](../../docs/evaluation.md) §7. `make
lab-preflight` covers L-0 and L-1, the security suite covers L-2 and L-4, and
`make lab-sanitize` covers L-5. **L-3 is yours**: the commit that publishes an excerpt has
to say, in words, that every system in the run was yours. In this lab that is true by
construction — the only systems are containers this file creates on your own machine — and
it is still worth writing down, because the day it stops being true is the day the sentence
becomes a lie somebody can see.

---

## What is here

| Path | What it is |
|---|---|
| `docker-compose.lab.yml` | The three services, the internal network, and every hardening declaration |
| `target/service.py` | The only listener: HTTP on 8080 (benign, 401, bulk), a second HTTP port 9443 for beacon check-ins, and a minimal DNS responder on 53. Its guarded path checks for a marker header, not a credential: no username or password exists anywhere in this lab |
| `generators/traffic.py` | The six shapes: benign, auth, sweep, beacon, bulk, dns |
| `suricata/suricata.yaml` | IDS-only sensor configuration: af-packet on one interface, EVE output, no payloads |
| `suricata/lab.rules` | Three alert-only rules in the reserved sid range 9100000-9199999 |
| `suricata/*.config` | Classification, reference and threshold files the lab owns, so nothing depends on the image's `/etc` |
| `out/` | Where the sensor writes. Ignored by git, emptied by `make lab-clean` |

### The six shapes and what each is for

| Scenario | What the generator does | Which rule it is aimed at |
|---|---|---|
| `benign` | 20 ordinary GETs carrying a marker header | Nothing — it is the noise the others sit in |
| `auth` | 12 requests that fail the target's authorisation check, answered 401 | D-002 auth-failure burst |
| `sweep` | One source, 40 closed ports on the one host the lab owns | D-001 port scan |
| `beacon` | 12 check-ins at a fixed five-second interval, on their own port (9443) | D-004 periodic beaconing |
| `bulk` | 4 MiB up and 4 MiB down | D-005 outbound volume |
| `dns` | 90 lookups over 30 rounds: hits, misses, and 60-character labels | D-003 DNS anomaly |

Nothing here is tuned to a threshold. The shapes are what an operator would call obvious;
whether the rules agree is the question, and the answer belongs in `docs/evaluation.md`,
not in the generator.

---

## Addressing

The lab lives in `203.0.113.0/24`, TEST-NET-3 from RFC 5737. Two reasons, and the second
one is the interesting one:

1. It is documentation space. It is never routed on the public internet, and
   `docs/evaluation.md` §1 rule 4 already reserves it for this project's data.
2. The detectors' explicit internal list
   ([`domain/detectors/addresses.py`](../../backend/src/aegisnet/domain/detectors/addresses.py))
   deliberately counts documentation ranges as **external**. Had the lab used an RFC 1918
   range, D-004 and D-005 would have skipped every packet it produced as internal-to-internal
   traffic, and the run would have proved nothing about them.

The target is fixed at `203.0.113.10` and the generator at `203.0.113.20`, so the seed file
(`samples/assets/lab-capture.yml`), the rules and this document can all name one address.
