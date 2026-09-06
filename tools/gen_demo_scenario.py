#!/usr/bin/env python3
"""Generate the multi-stage correlation scenario (Milestone 3, Chunk 17; ADR-025).

One host does four things in one hour — scans, fails to authenticate in a burst, beacons to
an external address, then uploads far more than it ever has — and a second, unrelated host
scans at the same time. That shape is the whole point: four rules on one entity must become
**one** incident with an escalated severity, and the unrelated host must get its own case
rather than being swept into the first.

The file is committed data with a pinned sha256, like the benign corpus, so `make eval` and
`make demo-scenario` measure the same bytes a reviewer can read. Everything here is
deterministic: one seed, fixed instants, no clock.

Two things this generator is careful about, both learned the hard way (ADR-022):

* a **flow** record is stamped when Suricata's flow manager emits it, and says when the
  conversation actually began in `flow.start`;
* it takes **no path argument** — the destination is a fixed name under the repository root
  it finds above its own working directory, which is the rule every tool here follows.

Run with `make gen-scenario`. Update `samples/registry.yml` with the printed sha256.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import random
from datetime import UTC, datetime, timedelta
from pathlib import Path

GENERATOR_VERSION = 1
SEED = 20260906

SCENARIO_FILE = Path("samples/scenarios/multi-stage-01.ndjson")
MANIFEST_FILE = Path("samples/scenarios/multi-stage-01.manifest.json")
LAYOUT = (Path("samples/registry.yml"), Path("tools/gen_demo_scenario.py"))

MIB = 1024 * 1024
SENSOR_INTERFACE = "lab0"

# The compromised host, and the second host that is merely noisy at the same moment. Both are
# RFC 1918; every destination is RFC 5737, which the detectors treat as external.
SUSPECT = "10.10.0.42"
BYSTANDER = "10.10.0.77"
SCAN_TARGET = "198.51.100.10"
BEACON_TARGET = "203.0.113.55"
UPLOAD_TARGET = "198.51.100.44"
UPDATE_MIRROR = "198.51.100.7"
AUTH_TARGET = "198.51.100.21"

# Seven days of history, then the hour everything happens in. The history exists so D-005 has
# a baseline to be surprised by: a rule that compares against history needs history, and a
# scenario that skipped it would be measuring a rule that abstains.
#
# Both sit before `adapters/files/labelled.EVALUATION_CLOCK` (2026-09-05T12:00Z), the fixed
# instant every committed corpus is judged against. A scenario dated after it would be refused
# as a future timestamp (T-1.7) by the very normaliser the demo is meant to exercise.
HISTORY_START = datetime(2026, 8, 29, 9, 0, tzinfo=UTC)
HISTORY_HOURS = 168
ATTACK_HOUR = datetime(2026, 9, 5, 9, 0, tzinfo=UTC)
# The same host, hours later, doing something separate. Six hours is far outside
# correlation's one-hour join gap, so this must be its own case even though the entity is
# identical — which is the only reason precision and contamination can be wrong at all.
LATER_HOUR = ATTACK_HOUR + timedelta(hours=6)
SWEEP_END = LATER_HOUR + timedelta(hours=1)

# Both signatures must read as an authentication failure to D-002, which matches its patterns
# against the signature *and* the category. Two of them, because a real brute force trips more
# than one rule and a scenario where every indicator is identical is a weaker test.
SSH_FAIL = (
    2001219,
    "ET SCAN Potential SSH Brute Force Attempt",
    "Attempted Administrator Privilege Gain",
)
SSH_FAIL_PASSWORD = (
    2001220,
    "ET EXPLOIT SSH failed password for invalid user",
    "Attempted Login",
)


class ScenarioError(ValueError):
    pass


def repository_root(start: Path) -> Path:
    """The nearest directory at or above ``start`` holding the whole layout."""
    for candidate in (start, *start.parents):
        if all((candidate / relative).exists() for relative in LAYOUT):
            return candidate
    raise ScenarioError(
        "not inside a repository checkout: "
        + ", ".join(str(relative) for relative in LAYOUT)
        + " were not all found at or above the working directory"
    )


def suricata_timestamp(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f") + "+0000"


class Renderer:
    """Deterministic EVE records in the shapes a real Suricata 8 sensor writes."""

    def __init__(self, seed: int) -> None:
        self.rng = random.Random(seed)  # noqa: S311 - reproducible data, not secrets
        self.next_flow_id = 9_100_000_000_000_000

    def flow(
        self,
        when: datetime,
        src: str,
        dst: str,
        dport: int,
        *,
        answered: bool,
        app_proto: str | None = None,
        bytes_out: int | None = None,
        bytes_in: int | None = None,
    ) -> dict:
        self.next_flow_id += 1
        if answered:
            pkts_out = self.rng.randint(6, 40)
            pkts_in = self.rng.randint(4, 30)
            counters = {
                "pkts_toserver": pkts_out,
                "pkts_toclient": pkts_in,
                "bytes_toserver": pkts_out * self.rng.randint(80, 900),
                "bytes_toclient": pkts_in * self.rng.randint(80, 1400),
                "state": "closed",
                "reason": "timeout",
            }
            if bytes_out is not None:
                counters["bytes_toserver"] = bytes_out
                counters["pkts_toserver"] = max(1, bytes_out // 1400)
            if bytes_in is not None:
                counters["bytes_toclient"] = bytes_in
                counters["pkts_toclient"] = max(1, bytes_in // 1400)
            age = self.rng.randint(1, 45)
        else:
            counters = {
                "pkts_toserver": 1,
                "pkts_toclient": 0,
                "bytes_toserver": 60,
                "bytes_toclient": 0,
                "state": "new",
                "reason": "timeout",
            }
            age = 0
        # `when` is when the conversation happened; the sensor stamps the record `age` seconds
        # later, when its flow manager emits it (ADR-022).
        emitted = when + timedelta(seconds=age)
        record: dict = {
            "timestamp": suricata_timestamp(emitted),
            "flow_id": self.next_flow_id,
            "in_iface": SENSOR_INTERFACE,
            "event_type": "flow",
            "src_ip": src,
            "src_port": self.rng.randint(32768, 60999),
            "dest_ip": dst,
            "dest_port": dport,
            "proto": "TCP",
            **({"app_proto": app_proto} if app_proto else {}),
            "flow": {
                **counters,
                "start": suricata_timestamp(when),
                "end": suricata_timestamp(emitted),
                "age": age,
                "alerted": False,
            },
        }
        record["tcp"] = (
            {"tcp_flags": "1b", "syn": True, "fin": True, "psh": True, "ack": True}
            if answered
            else {"tcp_flags": "02", "syn": True, "state": "syn_sent"}
        )
        return record

    def alert(
        self,
        when: datetime,
        src: str,
        dst: str,
        dport: int,
        sid: int,
        signature: str,
        category: str,
    ) -> dict:
        self.next_flow_id += 1
        return {
            "timestamp": suricata_timestamp(when),
            "flow_id": self.next_flow_id,
            "in_iface": SENSOR_INTERFACE,
            "event_type": "alert",
            "src_ip": src,
            "src_port": self.rng.randint(32768, 60999),
            "dest_ip": dst,
            "dest_port": dport,
            "proto": "TCP",
            "app_proto": "ssh",
            "tx_id": 0,
            "alert": {
                "action": "allowed",
                "gid": 1,
                "signature_id": sid,
                "rev": 1,
                "signature": signature,
                "category": category,
                "severity": 2,
            },
        }


# ---------------------------------------------------------------- the stages


def history(r: Renderer) -> list[dict]:
    """A week of ordinary outbound traffic, one modest transfer an hour.

    This is what makes D-005 able to speak: `recompute_baselines` turns these hours into the
    asset's mean, standard deviation and p95. Deliberately quiet and deliberately regular —
    an hour of it must never look like the spike, and one flow an hour can never reach
    D-004's ten connections inside its one-hour window.
    """
    records = []
    for hour in range(HISTORY_HOURS):
        when = HISTORY_START + timedelta(hours=hour, minutes=17)
        # 4 to 6 MiB an hour: enough spread for a real standard deviation, far under the 50 MiB
        # floor D-005 will not fire below.
        payload = int((4.0 + (hour % 7) * 0.3) * MIB)
        records.append(
            r.flow(
                when,
                SUSPECT,
                UPDATE_MIRROR,
                443,
                answered=True,
                app_proto="tls",
                bytes_out=payload,
                bytes_in=payload // 40,
            )
        )
    return records


def port_scan(r: Renderer, source: str, when: datetime, ports: int = 40) -> list[dict]:
    """A vertical scan: one host, many ports, nothing answering (D-001)."""
    return [
        r.flow(
            when + timedelta(seconds=index * 7),
            source,
            SCAN_TARGET,
            port,
            answered=False,
        )
        for index, port in enumerate(_scan_ports(ports))
    ]


def _scan_ports(count: int) -> list[int]:
    common = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 1521]
    return (common + list(range(3000, 3000 + count)))[:count]


def auth_burst(r: Renderer, when: datetime, failures: int = 12) -> list[dict]:
    """Twelve failed logins inside ninety seconds — the density D-002 asks for (D-002)."""
    records = []
    for index in range(failures):
        sid, signature, category = SSH_FAIL_PASSWORD if index % 2 else SSH_FAIL
        records.append(
            r.alert(
                when + timedelta(seconds=index * 7),
                SUSPECT,
                AUTH_TARGET,
                22,
                sid,
                signature,
                category,
            )
        )
    return records


def beacon(r: Renderer, when: datetime, connections: int = 14) -> list[dict]:
    """A check-in every sixty seconds, give or take a second (D-004).

    The jitter is real but small: a beacon that is perfectly regular is a fixture, and one
    that is irregular is a browser. A second either way is 1.6 % of the interval, well inside
    D-004's 15 % ceiling and well outside "this was generated by a loop with no clock".
    """
    drift = (0, 1, -1, 0, 1, 0, -1, 1, 0, -1, 0, 1, -1, 0)
    return [
        r.flow(
            when + timedelta(seconds=index * 60 + drift[index % len(drift)]),
            SUSPECT,
            BEACON_TARGET,
            8443,
            answered=True,
            app_proto="tls",
            bytes_out=1200 + index * 7,
            bytes_in=340,
        )
        for index in range(connections)
    ]


def exfiltration(r: Renderer, when: datetime) -> list[dict]:
    """One 400 MiB upload from a host whose week never exceeded six (D-005)."""
    return [
        r.flow(
            when,
            SUSPECT,
            UPLOAD_TARGET,
            443,
            answered=True,
            app_proto="tls",
            bytes_out=400 * MIB,
            bytes_in=90 * 1024,
        )
    ]


def build() -> tuple[list[dict], dict]:
    """Every record, in time order, and the ground truth that goes with it."""
    r = Renderer(SEED)
    records = history(r)
    records += port_scan(r, SUSPECT, ATTACK_HOUR + timedelta(minutes=2))
    records += auth_burst(r, ATTACK_HOUR + timedelta(minutes=12))
    records += beacon(r, ATTACK_HOUR + timedelta(minutes=20))
    records += exfiltration(r, ATTACK_HOUR + timedelta(minutes=40))
    # The unrelated host. Its only purpose is to be *not* part of the story: a correlation
    # engine that swept it into the first case would score a contamination above zero.
    records += port_scan(r, BYSTANDER, ATTACK_HOUR + timedelta(minutes=6), ports=32)
    # The same suspect, six hours later, doing something unconnected.
    records += port_scan(r, SUSPECT, LATER_HOUR + timedelta(minutes=3), ports=36)

    records.sort(key=lambda record: record["timestamp"])

    def span(start: datetime, hours: int = 1) -> dict[str, str]:
        return {
            "from": start.isoformat().replace("+00:00", "Z"),
            "to": (start + timedelta(hours=hours)).isoformat().replace("+00:00", "Z"),
        }

    # Ground truth is declared here, in terms of *when* and *what*, and never derived from the
    # thing being scored. Two of these scenarios share an entity: a truth read off the entity
    # key would make them one story, and grouping precision and contamination could then never
    # be anything but perfect (ADR-025).
    truth = {
        "scenarios": [
            {
                "id": "multi-stage-compromise",
                "entity": f"src_ip={SUSPECT}",
                "window": span(ATTACK_HOUR),
                "expected_rules": ["D-001", "D-002", "D-004", "D-005"],
                "narrative": (
                    "One host scans a neighbour, fails to authenticate twelve times in ninety "
                    "seconds, beacons to an external address every minute, and uploads 400 MiB "
                    "- all inside one hour."
                ),
            },
            {
                "id": "unrelated-scan",
                "entity": f"src_ip={BYSTANDER}",
                "window": span(ATTACK_HOUR),
                "expected_rules": ["D-001"],
                "narrative": (
                    "A second host scans the same neighbour in the same hour and has nothing "
                    "to do with the first. It must get its own case."
                ),
            },
            {
                "id": "later-unrelated-scan",
                "entity": f"src_ip={SUSPECT}",
                "window": span(LATER_HOUR),
                "expected_rules": ["D-001"],
                "narrative": (
                    "The suspect host scans again six hours later. Same entity, different "
                    "story: correlation's join gap is an hour, so folding this into the "
                    "morning's case would be wrong and is what the contamination measure "
                    "exists to catch."
                ),
            },
        ],
        "expected_incidents": 3,
    }
    return records, truth


def render(records: list[dict]) -> bytes:
    return "".join(json.dumps(record, separators=(",", ":")) + "\n" for record in records).encode()


def manifest_for(records: list[dict], truth: dict, digest: str) -> dict:
    counts: dict[str, int] = {}
    for record in records:
        counts[record["event_type"]] = counts.get(record["event_type"], 0) + 1
    return {
        "dataset_id": "demo-scenario-multi-stage-01",
        "generator": "tools/gen_demo_scenario.py",
        "generator_version": GENERATOR_VERSION,
        "seed": SEED,
        "events": len(records),
        "event_types": dict(sorted(counts.items())),
        "sha256": digest,
        "history": {
            "from": HISTORY_START.isoformat().replace("+00:00", "Z"),
            "hours": HISTORY_HOURS,
            "asset": SUSPECT,
        },
        "baseline_until": ATTACK_HOUR.isoformat().replace("+00:00", "Z"),
        "sweep_window": {
            "from": ATTACK_HOUR.isoformat().replace("+00:00", "Z"),
            "to": SWEEP_END.isoformat().replace("+00:00", "Z"),
        },
        "ground_truth": truth,
        "safety": (
            "Synthetic. RFC 1918 sources, RFC 5737 destinations, .test names only. No real "
            "host, address or credential appears here."
        ),
    }


def check_addresses(records: list[dict]) -> None:
    """Nothing routable, ever (docs/evaluation.md §1)."""
    allowed = [
        ipaddress.ip_network(cidr)
        for cidr in ("10.0.0.0/8", "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
    ]
    for record in records:
        for key in ("src_ip", "dest_ip"):
            address = ipaddress.ip_address(record[key])
            if not any(address in network for network in allowed):
                raise ScenarioError(f"{address} is outside the documentation ranges")


def write_all(scenario: Path, manifest: Path) -> tuple[int, str]:
    records, truth = build()
    check_addresses(records)
    payload = render(records)
    digest = hashlib.sha256(payload).hexdigest()
    scenario.parent.mkdir(parents=True, exist_ok=True)
    scenario.write_bytes(payload)
    manifest.write_text(json.dumps(manifest_for(records, truth, digest), indent=2) + "\n")
    return len(records), digest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args(argv)
    root = repository_root(Path.cwd())
    count, digest = write_all(root / SCENARIO_FILE, root / MANIFEST_FILE)
    print(f"wrote {count} events to {SCENARIO_FILE}")  # noqa: T201 - a generator's output
    print(f"sha256 {digest}")  # noqa: T201
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
