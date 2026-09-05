"""The lab's traffic generator: six shaped conversations with the lab target, and nothing else.

Every destination in this file is the lab target — by container name, or by an address
inside the lab subnet. There is no externally routable address here and no hostname outside
`example.test`; `backend/tests/security/test_lab_policy.py` asserts both, which is the
automated half of docs/evaluation.md §7 E-2. The generator never scans, probes or connects
to anything the lab did not create (docs/evaluation.md §1, rule 2).

The shapes exist so that a real Suricata capture contains something each detector can read:
sweep → D-001, auth → D-002, dns → D-003, beacon → D-004, bulk → D-005. Whether the
detectors then fire is exactly the question the lab exists to answer, so nothing here is
tuned to a threshold: the shapes are what an operator would call obvious.

Standard library only.
"""

from __future__ import annotations

import argparse
import base64
import http.client
import socket
import struct
import sys
import time
from dataclasses import dataclass
from pathlib import Path

# The lab target, by the name the lab's own Docker network resolves. Nothing else is ever
# contacted. `LAB_SUBNET` is documentation for the reader and for the policy test.
TARGET_HOST = "target"
LAB_SUBNET = "203.0.113.0/24"
LAB_ZONE = "lab.example.test"

MARKER_HEADER = "X-Aegisnet-Lab"
BEACON_PORT = 9443
LAB_USER = "lab-" + "operator"
WRONG_SECRET = "wrong-" + "on-purpose"

# Ports nobody listens on inside the lab. A connect() to each is refused immediately, which
# is the SYN/RST pattern a horizontal sweep leaves behind.
CLOSED_PORTS = tuple(range(30000, 30040))


@dataclass(frozen=True, slots=True)
class Counts:
    scenario: str
    attempted: int
    completed: int
    detail: str = ""


def _http(
    path: str,
    *,
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
    port: int = 8080,
) -> int:
    conn = http.client.HTTPConnection(TARGET_HOST, port, timeout=10)
    try:
        conn.request("POST" if body is not None else "GET", path, body=body, headers=headers or {})
        response = conn.getresponse()
        response.read()
        return response.status
    finally:
        conn.close()


def benign(rounds: int) -> Counts:
    """Ordinary requests, marked so the operator can find them in the capture."""
    done = 0
    headers = {MARKER_HEADER: "benign", "User-Agent": "aegisnet-lab/1"}
    for index in range(rounds):
        done += _http(f"/page/{index}", headers=headers) == 200
        time.sleep(0.2)
    return Counts("benign", rounds, done)


def auth_failures(rounds: int) -> Counts:
    """Wrong credentials against the lab's own guarded path: 401 after 401."""
    wrong = base64.b64encode(f"{LAB_USER}:{WRONG_SECRET}".encode()).decode()
    refused = 0
    for _ in range(rounds):
        refused += _http("/private", headers={"Authorization": f"Basic {wrong}"}) == 401
        time.sleep(0.3)
    return Counts("auth", rounds, refused, "401 responses")


def sweep() -> Counts:
    """One source, many closed ports on the one host the lab owns."""
    refused = 0
    for port in CLOSED_PORTS:
        sock = socket.socket()
        sock.settimeout(1.0)
        try:
            sock.connect((TARGET_HOST, port))
        except OSError:
            refused += 1
        finally:
            sock.close()
    return Counts("sweep", len(CLOSED_PORTS), refused, "connections refused")


def beacon(rounds: int, interval: float) -> Counts:
    """A regular check-in on its own port: the same destination at the same interval, over
    and over. The port matters — a beacon sharing a port with ordinary browsing is invisible
    to a rule that groups by destination and port, which is what the lab's first run found."""
    done = 0
    for _ in range(rounds):
        started = time.monotonic()
        done += _http("/beacon", headers={MARKER_HEADER: "beacon"}, port=BEACON_PORT) == 200
        time.sleep(max(0.0, interval - (time.monotonic() - started)))
    return Counts("beacon", rounds, done, f"every {interval:g}s to port {BEACON_PORT}")


def bulk(megabytes: int) -> Counts:
    """A large transfer in each direction, so the flow records carry real byte counts."""
    size = megabytes * 1024 * 1024
    down = _http(f"/bulk?bytes={size}")
    payload = (b"aegisnet-lab-upload-" * 52)[:1024] * megabytes * 1024
    up = _http(
        "/upload",
        headers={"Content-Type": "application/octet-stream", "Content-Length": str(len(payload))},
        body=payload,
    )
    return Counts("bulk", 2, (down == 200) + (up == 200), f"{megabytes} MiB each way")


def _query(name: str, *, timeout: float = 2.0) -> bool:
    """One A query to the lab's own resolver."""
    payload = b"\x13\x37" + struct.pack(">HHHHH", 0x0100, 1, 0, 0, 0)
    for label in name.split("."):
        payload += bytes([len(label)]) + label.encode("ascii")
    payload += b"\x00" + struct.pack(">HH", 1, 1)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(payload, (TARGET_HOST, 53))
        sock.recvfrom(4096)
        return True
    except OSError:
        return False
    finally:
        sock.close()


def dns(rounds: int) -> Counts:
    """Ordinary lookups, misses, and the long-label shape a tunnel would leave.

    Each round asks three distinct names, so the count is what decides whether the shape is
    unmistakable. A tunnel does not make six queries; it makes hundreds."""
    answered = 0
    for index in range(rounds):
        answered += _query(f"host{index}.{LAB_ZONE}")
        answered += _query(f"absent{index}.example.test")
        chunk = f"{index:02d}" + "abcdefghijklmnopqrstuvwxyz0123456789" * 2
        answered += _query(f"{chunk[:60]}.{chunk[:60]}.{LAB_ZONE}")
        time.sleep(0.2)
    return Counts("dns", rounds * 3, answered, "queries answered")


SCENARIOS = ("benign", "auth", "sweep", "beacon", "bulk", "dns")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--scenarios",
        default=",".join(SCENARIOS),
        help=f"comma-separated subset of: {', '.join(SCENARIOS)}",
    )
    parser.add_argument("--beacon-rounds", type=int, default=12)
    parser.add_argument("--beacon-interval", type=float, default=5.0)
    parser.add_argument("--bulk-mib", type=int, default=4)
    parser.add_argument("--dns-rounds", type=int, default=30)
    parser.add_argument(
        "--wait-for", default=None, help="file that must contain --wait-marker before starting"
    )
    parser.add_argument("--wait-marker", default="Engine started")
    parser.add_argument("--wait-seconds", type=float, default=60.0)
    args = parser.parse_args(argv)

    if args.wait_for and not _wait_for(args.wait_for, args.wait_marker, args.wait_seconds):
        print(  # noqa: T201 - CLI output
            f"generator: {args.wait_marker!r} never appeared in {args.wait_for}", file=sys.stderr
        )
        return 1

    chosen = [name for name in args.scenarios.split(",") if name]
    unknown = [name for name in chosen if name not in SCENARIOS]
    if unknown:
        parser.error(f"unknown scenario(s): {', '.join(unknown)}")

    runners = {
        "benign": lambda: benign(20),
        "auth": lambda: auth_failures(12),
        "sweep": sweep,
        "beacon": lambda: beacon(args.beacon_rounds, args.beacon_interval),
        "bulk": lambda: bulk(args.bulk_mib),
        "dns": lambda: dns(args.dns_rounds),
    }
    for name in chosen:
        started = time.monotonic()
        counts = runners[name]()
        elapsed = time.monotonic() - started
        print(  # noqa: T201
            f"generator: {counts.scenario} {counts.completed}/{counts.attempted} "
            f"{counts.detail} in {elapsed:.1f}s",
            flush=True,
        )
    print("generator: done", flush=True)  # noqa: T201
    return 0


def _wait_for(path: str, marker: str, seconds: float) -> bool:
    """Hold until Suricata says it is capturing, so no shaped traffic predates the sniffer."""
    deadline = time.monotonic() + seconds
    target = Path(path)
    while time.monotonic() < deadline:
        try:
            text = target.read_text(encoding="utf-8", errors="replace")
        except OSError:
            # The sensor has not created the file yet; that is the normal first few seconds.
            text = ""
        if marker in text:
            time.sleep(1.0)  # let the capture thread settle past the log line
            return True
        time.sleep(0.5)
    return False


if __name__ == "__main__":
    raise SystemExit(main())
