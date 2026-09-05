#!/usr/bin/env python3
"""Deterministic synthetic Suricata EVE JSON generator (decision D-5, ADR-009).

Standard library only, so it runs with any Python 3.12 without the backend environment.

Every run with the same seed and parameters produces byte-identical output. The corpus
describes a small, imaginary lab: a handful of internal hosts in an RFC 1918 range talking
to a DNS resolver and to "internet" services in RFC 5737 documentation ranges, with names
under example.test and example.com. Nothing here refers to a real system, and the
generator contains no capture, scan or traffic-sending capability of any kind.

Alongside the corpus it writes a manifest with the expected count per ``event_type``,
which the ingest acceptance test compares against what was stored.

No path is accepted on the command line: the corpus and its manifest are written at fixed
names under the repository root this script finds above its working directory.

Usage:
    python3 tools/gen_synthetic_eve.py --seed 20260905 --events 2000
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import random
import sys
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path

# 2: a flow record is stamped when Suricata emits it and carries the conversation's own
# start in `flow.start`, and DNS is written in the shape a current sensor writes — mostly
# EVE v3, where a request carries an `rcode` too. Both are what real Suricata does, and both
# were assumptions this generator had backwards (docs/evaluation.md §9, L-F1 and L-F2).
GENERATOR_VERSION = 2

CORPUS_FILE = Path("samples/synthetic/benign-baseline-01.ndjson")
# What identifies a checkout, for a script that must not be told where to write.
LAYOUT = (Path("samples/registry.yml"), Path("tools/gen_synthetic_eve.py"))


def repository_root(start: Path) -> Path:
    """The nearest directory at or above ``start`` that holds the whole layout."""
    for candidate in (start, *start.parents):
        if all((candidate / relative).exists() for relative in LAYOUT):
            return candidate
    raise FileNotFoundError(
        "not inside a repository checkout: "
        + ", ".join(str(relative) for relative in LAYOUT)
        + " were not all found at or above the working directory"
    )


SENSOR_INTERFACE = "lab0"

# RFC 1918 lab hosts and RFC 5737 "internet" endpoints. No real address can appear.
LAB_NETWORK = ipaddress.ip_network("10.10.0.0/24")
RESOLVER = "10.10.0.53"
GATEWAY = "10.10.0.1"
EXTERNAL_NETWORKS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
)
DOMAINS = (
    "www.example.test",
    "cdn.example.test",
    "updates.example.test",
    "mail.example.test",
    "api.example.com",
    "www.example.com",
    "static.example.com",
    "time.example.test",
)
USER_AGENTS = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/128.0 Safari/537.36",
    "curl/8.9.1",
    "python-requests/2.32.3",
    "Debian APT-HTTP/1.3 (2.9.8)",
)
URL_PATHS = (
    "/",
    "/index.html",
    "/api/v1/status",
    "/assets/app.js",
    "/dists/stable/Release",
    "/health",
)
TLS_VERSIONS = ("TLS 1.2", "TLS 1.3")
FILE_NAMES = ("/dists/stable/Release", "/assets/app.js", "/downloads/report.pdf", "/index.html")
FILE_MAGIC = (
    "ASCII text",
    "JavaScript source, ASCII text",
    "PDF document, version 1.7",
    "HTML document, ASCII text",
)

# Synthetic informational signatures. Deliberately named so nobody mistakes them for a
# real ruleset; severity 3 is Suricata's "low".
INFO_SIGNATURES = (
    (9000001, "AEGISNET-SYNTH INFO HTTP request to example.test", "Not Suspicious Traffic"),
    (9000002, "AEGISNET-SYNTH INFO TLS handshake with example.com", "Not Suspicious Traffic"),
)

# Benign event mix. Alerts are rare informational hits; everything else is ordinary traffic.
EVENT_WEIGHTS = {
    "flow": 44,
    "dns": 26,
    "http": 12,
    "tls": 12,
    "fileinfo": 3,
    "alert": 2,
    "anomaly": 1,
}


def suricata_timestamp(moment: datetime) -> str:
    """Suricata's format: microseconds and an offset without a colon."""
    return moment.strftime("%Y-%m-%dT%H:%M:%S.%f%z")


class Corpus:
    def __init__(self, seed: int, start: datetime, duration: timedelta, events: int) -> None:
        # Deterministic by design; nothing here is a secret.
        self.rng = random.Random(seed)  # noqa: S311
        self.start = start
        self.duration = duration
        self.total = events
        self.hosts = [str(LAB_NETWORK[i]) for i in range(10, 22)]
        self.external = [str(network[i]) for network in EXTERNAL_NETWORKS for i in range(10, 30)]
        self.domain_ip = {
            domain: self.external[i % len(self.external)] for i, domain in enumerate(DOMAINS)
        }
        self.pcap_cnt = 0
        self.counts: Counter[str] = Counter()

    # ------------------------------------------------------------------ helpers
    def _flow_id(self) -> int:
        return self.rng.getrandbits(53)

    def _base(
        self,
        when: datetime,
        event_type: str,
        src: str,
        sport: int,
        dst: str,
        dport: int,
        proto: str,
    ) -> dict:
        self.pcap_cnt += 1
        return {
            "timestamp": suricata_timestamp(when),
            "flow_id": self._flow_id(),
            "pcap_cnt": self.pcap_cnt,
            "in_iface": SENSOR_INTERFACE,
            "event_type": event_type,
            "src_ip": src,
            "src_port": sport,
            "dest_ip": dst,
            "dest_port": dport,
            "proto": proto,
        }

    def _ephemeral_port(self) -> int:
        return self.rng.randint(32768, 60999)

    def _flow_counters(self, scale: int = 1) -> dict:
        to_server = self.rng.randint(2, 40) * scale
        to_client = self.rng.randint(2, 60) * scale
        return {
            "pkts_toserver": to_server,
            "pkts_toclient": to_client,
            "bytes_toserver": to_server * self.rng.randint(60, 900),
            "bytes_toclient": to_client * self.rng.randint(60, 1400),
        }

    # ------------------------------------------------------------------ records
    def dns(self, when: datetime) -> list[dict]:
        host = self.rng.choice(self.hosts)
        domain = self.rng.choice(DOMAINS)
        port = self._ephemeral_port()
        tx_id = self.rng.randint(1, 65535)
        query = self._base(when, "dns", host, port, RESOLVER, 53, "UDP")
        # A fleet is not all one Suricata version, and the two EVE DNS shapes differ in a way
        # that has already cost this project a blind detector (docs/evaluation.md §9, L-F2):
        # v3 names the halves request/response and puts an `rcode` on *both*, while v2 names
        # them query/answer and puts one only on the answer. Most records are v3, what a
        # current sensor writes; one in five is v2, so the older shape stays covered.
        v3 = self.rng.random() > 0.2
        query["dns"] = (
            {
                "version": 3,
                "type": "request",
                "id": tx_id,
                "rcode": "NOERROR",
                "rd": True,
                "opcode": 0,
                "queries": [{"rrname": domain, "rrtype": "A"}],
                "tx_id": 0,
            }
            if v3
            else {
                "version": 2,
                "type": "query",
                "id": tx_id,
                "rrname": domain,
                "rrtype": "A",
                "tx_id": 0,
            }
        )
        answer = self._base(
            when + timedelta(milliseconds=self.rng.randint(2, 40)),
            "dns",
            RESOLVER,
            53,
            host,
            port,
            "UDP",
        )
        answer["flow_id"] = query["flow_id"]
        reply = {
            "rrname": domain,
            "rrtype": "A",
            "ttl": self.rng.choice((60, 300, 3600)),
            "rdata": self.domain_ip[domain],
        }
        answer["dns"] = (
            {
                "version": 3,
                "type": "response",
                "id": tx_id,
                "flags": "8180",
                "qr": True,
                "rd": True,
                "ra": True,
                "rcode": "NOERROR",
                "queries": [{"rrname": domain, "rrtype": "A"}],
                "answers": [reply],
                "tx_id": 0,
            }
            if v3
            else {
                "version": 2,
                "type": "answer",
                "id": tx_id,
                "flags": "8180",
                "qr": True,
                "rd": True,
                "ra": True,
                "rrname": domain,
                "rrtype": "A",
                "rcode": "NOERROR",
                "answers": [reply],
            }
        )
        return [query, answer]

    def http(self, when: datetime) -> list[dict]:
        host = self.rng.choice(self.hosts)
        domain = self.rng.choice(DOMAINS)
        record = self._base(
            when, "http", host, self._ephemeral_port(), self.domain_ip[domain], 80, "TCP"
        )
        record["tx_id"] = 0
        record["http"] = {
            "hostname": domain,
            "url": self.rng.choice(URL_PATHS),
            "http_user_agent": self.rng.choice(USER_AGENTS),
            "http_content_type": self.rng.choice(
                ("text/html", "application/json", "application/javascript")
            ),
            "http_method": self.rng.choice(("GET", "GET", "GET", "POST", "HEAD")),
            "protocol": "HTTP/1.1",
            "status": self.rng.choice((200, 200, 200, 200, 304, 404)),
            "length": self.rng.randint(0, 65535),
        }
        return [record]

    def tls(self, when: datetime) -> list[dict]:
        host = self.rng.choice(self.hosts)
        domain = self.rng.choice(DOMAINS)
        record = self._base(
            when, "tls", host, self._ephemeral_port(), self.domain_ip[domain], 443, "TCP"
        )
        record["tls"] = {
            "subject": f"CN={domain}",
            "issuerdn": "C=XX, O=Example Lab CA, CN=Example Lab Issuing CA",
            "serial": ":".join(f"{self.rng.randint(0, 255):02X}" for _ in range(8)),
            "fingerprint": ":".join(f"{self.rng.randint(0, 255):02x}" for _ in range(20)),
            "sni": domain,
            "version": self.rng.choice(TLS_VERSIONS),
            "notbefore": "2026-01-01T00:00:00",
            "notafter": "2027-01-01T00:00:00",
        }
        return [record]

    def flow(self, when: datetime) -> list[dict]:
        host = self.rng.choice(self.hosts)
        if self.rng.random() < 0.7:
            dst, dport, proto, app = (
                self.rng.choice(self.external),
                self.rng.choice((80, 443, 443, 443)),
                "TCP",
                "tls",
            )
            if dport == 80:
                app = "http"
        else:
            dst, dport, proto, app = RESOLVER, 53, "UDP", "dns"
        # `when` is when the conversation happened, and a flow record says so in `flow.start`.
        # The record's own timestamp is when Suricata's flow manager emitted it, `age` seconds
        # later — the ordering this generator had backwards until the isolated lab measured a
        # real sensor (docs/evaluation.md §9, L-F1).
        age = self.rng.randint(0, 120)
        emitted = when + timedelta(seconds=age)
        record = self._base(emitted, "flow", host, self._ephemeral_port(), dst, dport, proto)
        record["app_proto"] = app
        record["flow"] = {
            **self._flow_counters(),
            "start": suricata_timestamp(when),
            "end": suricata_timestamp(emitted),
            "age": age,
            "state": "closed" if proto == "TCP" else "established",
            "reason": "timeout",
            "alerted": False,
        }
        if proto == "TCP":
            record["tcp"] = {
                "tcp_flags": "1b",
                "syn": True,
                "fin": True,
                "psh": True,
                "ack": True,
                "state": "closed",
            }
        return [record]

    def fileinfo(self, when: datetime) -> list[dict]:
        host = self.rng.choice(self.hosts)
        domain = self.rng.choice(DOMAINS)
        index = self.rng.randrange(len(FILE_NAMES))
        record = self._base(
            when, "fileinfo", host, self._ephemeral_port(), self.domain_ip[domain], 80, "TCP"
        )
        record["app_proto"] = "http"
        record["tx_id"] = 0
        record["http"] = {
            "hostname": domain,
            "url": FILE_NAMES[index],
            "http_method": "GET",
            "protocol": "HTTP/1.1",
            "status": 200,
        }
        size = self.rng.randint(200, 200_000)
        record["fileinfo"] = {
            "filename": FILE_NAMES[index],
            "magic": FILE_MAGIC[index],
            "gaps": False,
            "state": "CLOSED",
            "sha256": hashlib.sha256(f"{domain}{FILE_NAMES[index]}{size}".encode()).hexdigest(),
            "stored": False,
            "size": size,
            "tx_id": 0,
        }
        return [record]

    def alert(self, when: datetime) -> list[dict]:
        host = self.rng.choice(self.hosts)
        sid, signature, category = self.rng.choice(INFO_SIGNATURES)
        domain = self.rng.choice(DOMAINS)
        dport = 80 if sid == 9000001 else 443
        record = self._base(
            when, "alert", host, self._ephemeral_port(), self.domain_ip[domain], dport, "TCP"
        )
        record["app_proto"] = "http" if dport == 80 else "tls"
        record["tx_id"] = 0
        record["alert"] = {
            "action": "allowed",
            "gid": 1,
            "signature_id": sid,
            "rev": 1,
            "signature": signature,
            "category": category,
            "severity": 3,
        }
        if dport == 80:
            record["http"] = {
                "hostname": domain,
                "url": "/",
                "http_method": "GET",
                "protocol": "HTTP/1.1",
                "status": 200,
            }
        else:
            record["tls"] = {"sni": domain, "version": "TLS 1.3"}
        record["flow"] = {
            **self._flow_counters(),
            "start": suricata_timestamp(when - timedelta(seconds=1)),
        }
        return [record]

    def anomaly(self, when: datetime) -> list[dict]:
        host = self.rng.choice(self.hosts)
        record = self._base(
            when,
            "anomaly",
            host,
            self._ephemeral_port(),
            self.rng.choice(self.external),
            443,
            "TCP",
        )
        record["anomaly"] = {"type": "stream", "event": "stream.pkt_broken_ack"}
        return [record]

    # ------------------------------------------------------------------ driver
    def generate(self) -> list[dict]:
        kinds = list(EVENT_WEIGHTS)
        weights = [EVENT_WEIGHTS[kind] for kind in kinds]
        producers = {
            "dns": self.dns,
            "http": self.http,
            "tls": self.tls,
            "flow": self.flow,
            "fileinfo": self.fileinfo,
            "alert": self.alert,
            "anomaly": self.anomaly,
        }
        records: list[dict] = []
        moment = self.start
        step = self.duration / self.total
        while len(records) < self.total:
            moment += step * self.rng.uniform(0.2, 1.8)
            kind = self.rng.choices(kinds, weights)[0]
            for record in producers[kind](moment):
                if len(records) == self.total:
                    break
                records.append(record)
                self.counts[record["event_type"]] += 1
        records.sort(key=lambda r: (r["timestamp"], r["pcap_cnt"]))
        return records


def render(records: list[dict]) -> bytes:
    lines = [json.dumps(record, separators=(",", ":"), ensure_ascii=True) for record in records]
    return ("\n".join(lines) + "\n").encode("ascii")


def manifest_for(
    args: argparse.Namespace, corpus: Corpus, payload: bytes, records: list[dict]
) -> dict:
    return {
        "generator": "tools/gen_synthetic_eve.py",
        "generator_version": GENERATOR_VERSION,
        "seed": args.seed,
        "events": len(records),
        "counts_by_type": dict(sorted(corpus.counts.items())),
        "time_range": {"start": records[0]["timestamp"], "end": records[-1]["timestamp"]},
        "sha256": hashlib.sha256(payload).hexdigest(),
        "size_bytes": len(payload),
        "addressing": "RFC 1918 lab hosts (10.10.0.0/24) and RFC 5737 documentation ranges only",
        "names": "example.test and example.com only",
        "content": (
            "benign baseline traffic; the only alerts are synthetic informational "
            "signatures (sid 9000001-9000002)"
        ),
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--seed", type=int, default=20260905)
    parser.add_argument("--events", type=int, default=2000)
    parser.add_argument("--start", default="2026-09-01T00:00:00Z", help="ISO 8601, UTC")
    parser.add_argument("--duration-minutes", type=int, default=120)
    return parser.parse_args(argv)


def write_corpus(out: Path, args: argparse.Namespace) -> tuple[int, int, Path]:
    """Render the corpus and its manifest at ``out``; returns events, bytes and the manifest."""
    start = datetime.fromisoformat(args.start.replace("Z", "+00:00")).astimezone(UTC)
    corpus = Corpus(args.seed, start, timedelta(minutes=args.duration_minutes), args.events)
    records = corpus.generate()
    payload = render(records)
    manifest_path = out.with_name(f"{out.stem}.manifest.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(payload)
    manifest_path.write_text(
        json.dumps(manifest_for(args, corpus, payload, records), indent=2) + "\n", encoding="utf-8"
    )
    return len(records), len(payload), manifest_path


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.events < 1:
        print("--events must be positive", file=sys.stderr)  # noqa: T201 - CLI
        return 2
    try:
        out = repository_root(Path.cwd()) / CORPUS_FILE
    except FileNotFoundError as error:
        print(f"error: {error}", file=sys.stderr)  # noqa: T201 - CLI
        return 1
    events, size, manifest_path = write_corpus(out, args)
    print(f"wrote {events} events to {CORPUS_FILE} ({size} bytes); manifest {manifest_path.name}")  # noqa: T201
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
