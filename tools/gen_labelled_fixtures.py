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

    def alert(
        self,
        when: datetime,
        src: str,
        dst: str,
        dport: int,
        sid: int,
        signature: str,
        category: str,
        *,
        app_proto: str = "ssh",
    ) -> dict:
        """A Suricata signature hit; the auth-failure indicators D-002 reads."""
        self.next_flow_id += 1
        return {
            "timestamp": suricata_timestamp(when),
            "flow_id": self.next_flow_id,
            "in_iface": "lab0",
            "event_type": "alert",
            "src_ip": src,
            "src_port": self.rng.randint(32768, 60999),
            "dest_ip": dst,
            "dest_port": dport,
            "proto": "TCP",
            "app_proto": app_proto,
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

    def dns(
        self,
        when: datetime,
        client: str,
        name: str,
        *,
        rrtype: str = "A",
        rcode: str | None = "NOERROR",
        resolver: str = "10.10.0.53",
    ) -> list[dict]:
        """A query record from the client and, unless ``rcode`` is None, the answer record
        from the resolver carrying the rcode, the way Suricata logs both directions."""
        self.next_flow_id += 1
        flow_id = self.next_flow_id
        port = self.rng.randint(32768, 60999)
        tx_id = self.rng.randint(1, 65535)
        base = {
            "in_iface": "lab0",
            "event_type": "dns",
            "proto": "UDP",
            "flow_id": flow_id,
        }
        query = {
            **base,
            "timestamp": suricata_timestamp(when),
            "src_ip": client,
            "src_port": port,
            "dest_ip": resolver,
            "dest_port": 53,
            "dns": {
                "version": 2,
                "type": "query",
                "id": tx_id,
                "rrname": name,
                "rrtype": rrtype,
                "tx_id": 0,
            },
        }
        if rcode is None:
            return [query]
        answer = {
            **base,
            "timestamp": suricata_timestamp(when + timedelta(milliseconds=self.rng.randint(2, 40))),
            "src_ip": resolver,
            "src_port": 53,
            "dest_ip": client,
            "dest_port": port,
            "dns": {
                "version": 2,
                "type": "answer",
                "id": tx_id,
                "flags": "8180" if rcode == "NOERROR" else "8183",
                "qr": True,
                "rd": True,
                "ra": True,
                "rrname": name,
                "rrtype": rrtype,
                "rcode": rcode,
                "answers": [{"rrname": name, "rrtype": rrtype, "ttl": 300, "rdata": "192.0.2.10"}]
                if rcode == "NOERROR"
                else [],
            },
        }
        return [query, answer]

    def label(self, length: int, alphabet: str = "abcdefghijklmnopqrstuvwxyz0123456789") -> str:
        return "".join(self.rng.choice(alphabet) for _ in range(length))


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


# ---------------------------------------------------------------- D-002 cases

SSH_FAIL = (
    2001219,
    "ET SCAN Potential SSH Brute Force Attempt",
    "Attempted Administrator Privilege Gain",
)
WEB_FAIL = (
    2014020,
    "ET WEB_SERVER WordPress Login Failure - Brute Force",
    "Attempted User Privilege Gain",
)
RDP_FAIL = (
    2001972,
    "ET SCAN RDP Brute Force Login Attempt",
    "Attempted Administrator Privilege Gain",
)
INFO_ALERT = (
    2100498,
    "ET INFO Session Traversal Utilities for NAT (STUN Binding Request)",
    "Misc activity",
)


def ssh_brute(r: Renderer) -> list[dict]:
    sid, sig, cat = SSH_FAIL
    return [
        r.alert(when, "10.10.0.66", "10.10.0.20", 22, sid, sig, cat)
        for when in spread(WINDOW_START + timedelta(seconds=20), 90, 200)
    ]


def http_login_burst(r: Renderer) -> list[dict]:
    sid, sig, cat = WEB_FAIL
    return [
        r.alert(when, "10.10.0.67", "10.10.0.30", 443, sid, sig, cat, app_proto="http")
        for when in spread(WINDOW_START + timedelta(minutes=3), 100, 60)
    ]


def spray_two_services_with_noise(r: Renderer) -> list[dict]:
    records = []
    for when in spread(WINDOW_START + timedelta(seconds=5), 60, 12):
        records.append(r.alert(when, "10.10.0.68", "10.10.0.20", 22, *SSH_FAIL))
    for when in spread(WINDOW_START + timedelta(seconds=8), 60, 12):
        records.append(r.alert(when, "10.10.0.68", "10.10.0.31", 3389, *RDP_FAIL, app_proto="rdp"))
    hosts = ["10.10.0.11", "10.10.0.12", "10.10.0.13"]
    for index, when in enumerate(spread(WINDOW_START, 590, 40)):
        records.append(
            r.alert(when, hosts[index % 3], "192.0.2.10", 443, *INFO_ALERT, app_proto="tls")
        )
    for index, when in enumerate(spread(WINDOW_START + timedelta(seconds=1), 590, 30)):
        records.append(r.flow(when, hosts[index % 3], "192.0.2.10", 443, answered=True))
    return records


def fat_finger_then_success(r: Renderer) -> list[dict]:
    records = [
        r.alert(when, "10.10.0.21", "10.10.0.20", 22, *SSH_FAIL)
        for when in spread(WINDOW_START + timedelta(seconds=10), 20, 3)
    ]
    records += [
        r.flow(when, "10.10.0.21", "10.10.0.20", 22, answered=True)
        for when in spread(WINDOW_START + timedelta(seconds=40), 500, 20)
    ]
    return records


def monitoring_probe_steady(r: Renderer) -> list[dict]:
    return [
        r.alert(
            WINDOW_START + timedelta(seconds=5 + 60 * i), "10.10.0.5", "10.10.0.20", 22, *SSH_FAIL
        )
        for i in range(10)
    ]


def unrelated_alert_volume(r: Renderer) -> list[dict]:
    return [
        r.alert(when, "10.10.0.14", "192.0.2.10", 443, *INFO_ALERT, app_proto="tls")
        for when in spread(WINDOW_START + timedelta(seconds=2), 590, 100)
    ]


def eight_failures_under_threshold(r: Renderer) -> list[dict]:
    return [
        r.alert(when, "10.10.0.22", "10.10.0.20", 22, *SSH_FAIL)
        for when in spread(WINDOW_START + timedelta(seconds=30), 30, 8)
    ]


# ---------------------------------------------------------------- D-003 cases


def tunnel_random_subdomains(r: Renderer) -> list[dict]:
    records = []
    for when in spread(WINDOW_START + timedelta(seconds=3), 560, 300):
        records += r.dns(
            when,
            "10.10.0.71",
            f"{r.label(40, '0123456789abcdef')}.t.exfil-example.com",
            rrtype="TXT",
        )
    return records


def nxdomain_storm(r: Renderer) -> list[dict]:
    records = []
    for index, when in enumerate(spread(WINDOW_START + timedelta(seconds=4), 570, 120)):
        tld = r.rng.choice(("com", "net", "org", "info"))
        name = f"{r.label(12, 'abcdefghijklmnopqrstuvwxyz')}.{tld}"
        records += r.dns(when, "10.10.0.72", name, rcode="NXDOMAIN" if index % 12 else "NOERROR")
    return records


def long_labels_c2(r: Renderer) -> list[dict]:
    records = []
    for when in spread(WINDOW_START + timedelta(seconds=6), 500, 40):
        records += r.dns(
            when, "10.10.0.73", f"{r.label(48, 'abcdefghijklmnopqrstuvwxyz234567')}.c2.example.net"
        )
    return records


CDN_HOSTS = [
    "d3k1n2j4f5g6h7.cloudfront.net",
    "a1b2c3d4e5f6.execute-api.eu-west-1.amazonaws.com",
    "e13342.dscb.akamaiedge.net",
    "xyzstorage123.blob.core.windows.net",
    "lh3.googleusercontent.com",
    "assets-cdn-8f3k2.fastly.net",
    "v10.events.data.microsoft.com",
    "gspe1-ssl.ls.apple.com",
]


def cdn_cloud_hostnames(r: Renderer) -> list[dict]:
    records = []
    for index, when in enumerate(spread(WINDOW_START + timedelta(seconds=2), 590, 120)):
        records += r.dns(when, "10.10.0.15", CDN_HOSTS[index % len(CDN_HOSTS)])
    return records


def resolver_high_volume(r: Renderer) -> list[dict]:
    records = []
    for index, when in enumerate(spread(WINDOW_START + timedelta(seconds=1), 595, 400)):
        name = f"svc{index % 150:03d}.example.org"
        records += r.dns(
            when,
            "10.10.0.53",
            name,
            rcode="NXDOMAIN" if index % 20 == 0 else "NOERROR",
            resolver="192.0.2.53",
        )
    return records


def dnssec_txt_heavy(r: Renderer) -> list[dict]:
    records = []
    domains = [f"mail{i:02d}.example.com" for i in range(30)]
    shapes = [
        ("_dmarc.{d}", "TXT"),
        ("default._domainkey.{d}", "TXT"),
        ("{d}", "DNSKEY"),
        ("{d}", "DS"),
        ("{d}", "TXT"),
    ]
    for index, when in enumerate(spread(WINDOW_START + timedelta(seconds=2), 590, 100)):
        pattern, rrtype = shapes[index % len(shapes)]
        records += r.dns(when, "10.10.0.16", pattern.format(d=domains[index % 30]), rrtype=rrtype)
    return records


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
        "D-002",
        "positive",
        "ssh-brute-200-in-90s",
        "200 SSH brute-force alerts from one source against one host in 90 seconds.",
        ssh_brute,
        ("src_ip", "10.10.0.66"),
        3,
    ),
    Case(
        "D-002",
        "positive",
        "http-login-failures-60",
        "60 web login-failure alerts from one source against one host in 100 seconds.",
        http_login_burst,
        ("src_ip", "10.10.0.67"),
        3,
    ),
    Case(
        "D-002",
        "positive",
        "spray-two-services-with-noise",
        (
            "12 SSH and 12 RDP failure alerts from one source in a minute, among 40 informational "
            "alerts and 30 answered flows from other hosts; only the sprayer may alert."
        ),
        spray_two_services_with_noise,
        ("src_ip", "10.10.0.68"),
        3,
    ),
    Case(
        "D-002",
        "negative",
        "fat-finger-three-then-success",
        "Three failures in twenty seconds, then a normal SSH session: far under the threshold.",
        fat_finger_then_success,
    ),
    Case(
        "D-002",
        "negative",
        "monitoring-probe-steady",
        (
            "A monitoring probe with an invalid credential once a minute: ten failures in the "
            "window, the threshold count, but never more than three in any two-minute span. The "
            "hard negative: counting the window alone would flag it."
        ),
        monitoring_probe_steady,
    ),
    Case(
        "D-002",
        "negative",
        "unrelated-alerts-volume",
        "100 informational alerts from one source with no authentication signature or category.",
        unrelated_alert_volume,
    ),
    Case(
        "D-002",
        "negative",
        "eight-failures-under-threshold",
        "Eight failures in thirty seconds: a burst, but under the count.",
        eight_failures_under_threshold,
    ),
    Case(
        "D-003",
        "positive",
        "tunnel-random-subdomains-txt",
        (
            "300 distinct TXT queries for 40-hex-character labels under one domain from one "
            "client, all answered."
        ),
        tunnel_random_subdomains,
        ("src_ip", "10.10.0.71"),
        3,
    ),
    Case(
        "D-003",
        "positive",
        "nxdomain-storm-dga",
        "120 queries for random twelve-letter domains from one client, 110 of them NXDOMAIN.",
        nxdomain_storm,
        ("src_ip", "10.10.0.72"),
        3,
    ),
    Case(
        "D-003",
        "positive",
        "long-labels-c2",
        "40 distinct queries carrying a 48-character label under one domain, answered.",
        long_labels_c2,
        ("src_ip", "10.10.0.73"),
        3,
    ),
    Case(
        "D-003",
        "negative",
        "cdn-cloud-hostnames",
        (
            "120 queries cycling through eight random-looking CDN and cloud hostnames: "
            "allow-listed suffixes, eight distinct names."
        ),
        cdn_cloud_hostnames,
    ),
    Case(
        "D-003",
        "negative",
        "resolver-high-volume",
        (
            "A resolver forwarding 400 queries for 150 hosts of one organisation with 5% "
            "NXDOMAIN. The hard negative: 150 distinct subdomains under one domain would trip a "
            "unique-subdomain count; the tunnel signal also needs half of them to be long "
            "high-entropy labels."
        ),
        resolver_high_volume,
    ),
    Case(
        "D-003",
        "negative",
        "dnssec-txt-heavy",
        (
            "100 DMARC, DKIM, DNSKEY and DS lookups across 30 mail domains: TXT-heavy, "
            "low entropy, no failures."
        ),
        dnssec_txt_heavy,
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


RULE_DIRS = {"D-001": "port-scan", "D-002": "auth-burst", "D-003": "dns-anomaly"}


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
