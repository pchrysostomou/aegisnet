#!/usr/bin/env python3
"""Render the labelled T1 detector fixtures (docs/evaluation.md sections 2 and 3) from the case
definitions below.

Every case is a short, reviewable description: who talks to whom, how often, answered or
not. The rendered ``events.ndjson`` (Suricata EVE ``flow`` records) and ``labels.yml``
are committed under ``backend/tests/fixtures/labelled/<rule>/<positive|negative>/<case>/``
and are byte-identical on regeneration: every ephemeral port and jitter comes from a
seeded generator, and the test suite fails if the committed files drift from this script.

Usage:
    python3 tools/gen_labelled_fixtures.py --out backend/tests/fixtures/labelled
"""

from __future__ import annotations

import argparse
import json
import random
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

SEED = 20260905
WINDOW_START = datetime(2026, 9, 1, 10, 0, tzinfo=UTC)
WINDOW_END = WINDOW_START + timedelta(minutes=10)

VERTICAL_PORTS = [
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    111,
    135,
    139,
    143,
    443,
    445,
    465,
    587,
    993,
    995,
    1433,
    1521,
    2049,
    3306,
    3389,
    5432,
    5900,
    5985,
    6379,
    8000,
    8080,
    8443,
    8888,
    9000,
    9090,
    9200,
    9300,
    10000,
    11211,
    27017,
    50000,
    50070,
    61616,
]  # 40 distinct ports


def suricata_timestamp(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%S.%f") + "+0000"


class Renderer:
    """Deterministic EVE ``flow`` records. Unanswered flows are what a scan leaves behind:
    packets to the server, nothing back, state ``new``."""

    def __init__(self, seed: int) -> None:
        self.rng = random.Random(seed)  # noqa: S311 - reproducible fixtures, not secrets
        self.next_flow_id = 7_000_000_000_000_000

    def flow(
        self,
        when: datetime,
        src: str,
        dst: str,
        dport: int,
        *,
        answered: bool,
        proto: str = "TCP",
    ) -> dict:
        self.next_flow_id += 1
        sport = self.rng.randint(32768, 60999)
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
        start = when - timedelta(seconds=age)
        record = {
            "timestamp": suricata_timestamp(when),
            "flow_id": self.next_flow_id,
            "in_iface": "lab0",
            "event_type": "flow",
            "src_ip": src,
            "src_port": sport,
            "dest_ip": dst,
            "dest_port": dport,
            "proto": proto,
            "flow": {
                **counters,
                "start": suricata_timestamp(start),
                "end": suricata_timestamp(when),
                "age": age,
                "alerted": False,
            },
        }
        if proto == "TCP":
            record["tcp"] = (
                {
                    "tcp_flags": "1b",
                    "syn": True,
                    "fin": True,
                    "psh": True,
                    "ack": True,
                    "state": "closed",
                }
                if answered
                else {"tcp_flags": "02", "syn": True, "state": "syn_sent"}
            )
        return record


def spread(start: datetime, seconds: float, count: int) -> Iterator[datetime]:
    """``count`` instants evenly spaced over ``seconds``, starting at ``start``."""
    step = seconds / max(count, 1)
    for index in range(count):
        yield start + timedelta(seconds=index * step)


@dataclass(frozen=True)
class Case:
    rule_id: str
    kind: str  # positive | negative
    name: str
    notes: str
    build: Callable[[Renderer], list[dict]]
    expected_entity: tuple[str, str] | None = None
    expected_min_severity: int | None = None

    @property
    def case_id(self) -> str:
        return f"{self.rule_id}-{'pos' if self.kind == 'positive' else 'neg'}-{self.name}"


# ---------------------------------------------------------------- D-001 cases


def vertical_scan(r: Renderer) -> list[dict]:
    return [
        r.flow(when, "10.10.0.99", "10.10.0.20", port, answered=False)
        for when, port in zip(
            spread(WINDOW_START + timedelta(seconds=30), 120, 40), VERTICAL_PORTS, strict=False
        )
    ]


def horizontal_scan(r: Renderer) -> list[dict]:
    return [
        r.flow(when, "10.10.0.99", f"10.10.0.{host}", 445, answered=False)
        for when, host in zip(
            spread(WINDOW_START + timedelta(seconds=15), 90, 30), range(101, 131), strict=False
        )
    ]


def mixed_scan_with_noise(r: Renderer) -> list[dict]:
    records = []
    targets = [(f"10.10.0.{host}", port) for host in range(131, 156) for port in (22, 3389)]
    for when, (host, port) in zip(
        spread(WINDOW_START + timedelta(seconds=5), 480, len(targets)), targets, strict=False
    ):
        records.append(r.flow(when, "10.10.0.77", host, port, answered=False))
    # Benign background from three other workstations: web and DNS, all answered.
    sources = ["10.10.0.11", "10.10.0.12", "10.10.0.13"]
    for index, when in enumerate(spread(WINDOW_START, 590, 60)):
        src = sources[index % 3]
        if index % 4 == 3:
            records.append(r.flow(when, src, "10.10.0.53", 53, answered=True, proto="UDP"))
        else:
            records.append(r.flow(when, src, "192.0.2.10", 443, answered=True))
    return records


def lb_health_checks(r: Renderer) -> list[dict]:
    records = []
    for round_index in range(5):
        base = WINDOW_START + timedelta(minutes=2 * round_index)
        for host_index, host in enumerate(range(21, 25)):
            for port_index, port in enumerate((80, 443, 8080)):
                when = base + timedelta(seconds=host_index * 5 + port_index)
                records.append(r.flow(when, "10.10.0.5", f"10.10.0.{host}", port, answered=True))
    return records


def backup_client(r: Renderer) -> list[dict]:
    return [
        r.flow(when, "10.10.0.31", "10.10.0.20", 22, answered=True)
        for when in spread(WINDOW_START + timedelta(seconds=2), 590, 200)
    ]


def service_discovery(r: Renderer) -> list[dict]:
    records = []
    for round_index in range(2):
        base = WINDOW_START + timedelta(minutes=4 * round_index)
        for host_index, host in enumerate(range(41, 49)):
            for port_index, port in enumerate((80, 443)):
                when = base + timedelta(seconds=host_index * 3 + port_index)
                records.append(r.flow(when, "10.10.0.40", f"10.10.0.{host}", port, answered=True))
    return records


def dns_client_bursts(r: Renderer) -> list[dict]:
    return [
        r.flow(when, "10.10.0.15", "10.10.0.53", 53, answered=True, proto="UDP")
        for when in spread(WINDOW_START + timedelta(seconds=1), 595, 300)
    ]


CASES: list[Case] = [
    Case(
        "D-001",
        "positive",
        "vertical-40-ports",
        "One source, one host, 40 distinct ports in two minutes, no replies (SYN scan shape).",
        vertical_scan,
        ("src_ip", "10.10.0.99"),
        3,
    ),
    Case(
        "D-001",
        "positive",
        "horizontal-30-hosts-445",
        "One source, port 445 on 30 hosts in 90 seconds, no replies.",
        horizontal_scan,
        ("src_ip", "10.10.0.99"),
        3,
    ),
    Case(
        "D-001",
        "positive",
        "mixed-with-noise",
        (
            "25 hosts x 2 ports over eight minutes from one source, buried in 60 answered web and "
            "DNS flows from three other workstations; only the scanner may alert."
        ),
        mixed_scan_with_noise,
        ("src_ip", "10.10.0.77"),
        3,
    ),
    Case(
        "D-001",
        "negative",
        "lb-health-checks",
        (
            "A load balancer probing 4 backends on 3 ports every two minutes: 60 answered flows, "
            "12 distinct targets, well under both thresholds."
        ),
        lb_health_checks,
    ),
    Case(
        "D-001",
        "negative",
        "backup-client-one-port",
        (
            "A backup client opening 200 connections to one host on port 22. The hard negative: "
            "counting connections instead of distinct (host, port) targets would flag it."
        ),
        backup_client,
    ),
    Case(
        "D-001",
        "negative",
        "service-discovery-within-threshold",
        (
            "Service discovery over 8 hosts x 2 ports, twice: 32 answered flows, 16 targets, 8 "
            "hosts and 2 ports, below both thresholds."
        ),
        service_discovery,
    ),
    Case(
        "D-001",
        "negative",
        "dns-client-bursts",
        "A client sending 300 DNS queries to the resolver in ten minutes: one target, answered.",
        dns_client_bursts,
    ),
]


def labels_for(case: Case) -> str:
    lines = [
        f"case_id: {case.case_id}",
        f"rule_id: {case.rule_id}",
        f"expected: {'detection' if case.kind == 'positive' else 'no_detection'}",
    ]
    if case.expected_entity is not None:
        kind, value = case.expected_entity
        lines.append(f'expected_entity: {{ type: {kind}, value: "{value}" }}')
    if case.expected_min_severity is not None:
        lines.append(f"expected_min_severity: {case.expected_min_severity}")
    lines.append(
        f'window: {{ start: "{WINDOW_START.strftime("%Y-%m-%dT%H:%M:%SZ")}", '
        f'end: "{WINDOW_END.strftime("%Y-%m-%dT%H:%M:%SZ")}" }}'
    )
    lines.append(f'notes: "{case.notes}"')
    return "\n".join(lines) + "\n"


def render(case: Case) -> tuple[bytes, str]:
    # One generator per case, seeded by the case id: adding a case never changes another.
    seed = SEED + sum(ord(c) for c in case.case_id)
    records = sorted(case.build(Renderer(seed)), key=lambda r: (r["timestamp"], r["flow_id"]))
    body = "".join(json.dumps(r, separators=(",", ":"), sort_keys=True) + "\n" for r in records)
    return body.encode("utf-8"), labels_for(case)


def write_all(out: Path) -> list[Path]:
    written = []
    for case in CASES:
        directory = out / f"{case.rule_id}-{RULE_DIRS[case.rule_id]}" / case.kind / case.name
        directory.mkdir(parents=True, exist_ok=True)
        events, labels = render(case)
        (directory / "events.ndjson").write_bytes(events)
        (directory / "labels.yml").write_text(labels, encoding="utf-8")
        written.append(directory)
    return written


RULE_DIRS = {"D-001": "port-scan"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--out", type=Path, required=True, help="the labelled fixtures root")
    args = parser.parse_args(argv)
    for directory in write_all(args.out):
        events = directory / "events.ndjson"
        count = sum(1 for _ in events.open("rb"))
        print(f"{directory.relative_to(args.out)}: {count} events")  # noqa: T201 - CLI
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
