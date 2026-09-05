"""L-0, asked of a running lab container rather than read off the manifest.

Two checks, because the first alone is not enough:

* the container has no default route — that is what ``internal: true`` removes;
* and nothing on the lab subnet answers except the lab. Docker normally puts the subnet's
  first address on the host side of the bridge, and a container can reach *that* with no
  default route at all, so a route table saying "no default" proves less than it looks.
  The lab's network sets ``inhibit_ipv4`` so the bridge has no address; this asks whether
  that worked, by trying to connect.

Exits non-zero if anything is reachable, which fails ``make lab-preflight`` and stops a run
before a packet is generated.
"""

from __future__ import annotations

import ipaddress
import socket
import sys
from pathlib import Path

# A public address, which must be unreachable for the obvious reason. The bridge address is
# not hard-coded: it is derived from the container's own on-link route, so changing the
# lab's subnet cannot quietly turn this check into a check of nothing.
OUTSIDE = "192.0.2.1"
PORTS = (22, 111, 443, 5432, 8000, 9000)
TIMEOUT = 2.0


def _routes() -> list[list[str]]:
    return [line.split() for line in Path("/proc/net/route").read_text().splitlines()[1:]]


def default_routes() -> list[str]:
    return [row[0] for row in _routes() if len(row) > 1 and row[1] == "00000000"]


def _little_endian(hex_word: str) -> int:
    return int.from_bytes(bytes.fromhex(hex_word), "little")


def bridge_addresses() -> list[str]:
    """The first address of every subnet this container is on-link with — the address Docker
    gives the host side of a bridge when it is not told to leave it off."""
    found: list[str] = []
    for row in _routes():
        if len(row) < 8 or row[1] == "00000000":
            continue
        prefix = bin(_little_endian(row[7])).count("1")
        network = ipaddress.ip_network(
            (ipaddress.IPv4Address(_little_endian(row[1])), prefix), strict=False
        )
        candidate = str(network.network_address + 1)
        if candidate not in found:
            found.append(candidate)
    return found


def reachable(host: str, port: int) -> bool:
    """True when something answered — including a refusal, which means the packet arrived."""
    sock = socket.socket()
    sock.settimeout(TIMEOUT)
    try:
        sock.connect((host, port))
    except ConnectionRefusedError:
        return True  # a refusal is a reply: the address exists and is routed
    except OSError:
        return False
    else:
        return True
    finally:
        sock.close()


def main() -> int:
    routes = default_routes()
    bridges = bridge_addresses()
    print(f"  default routes: {routes or 'none'}")  # noqa: T201 - CLI output
    print(f"  first address of each on-link subnet: {bridges or 'none'}")  # noqa: T201
    answered = [
        f"{host}:{port}" for host in [*bridges, OUTSIDE] for port in PORTS if reachable(host, port)
    ]
    print(f"  answered on the lab subnet or outside it: {answered or 'nothing'}")  # noqa: T201
    if routes:
        print("  FAIL: the lab has a default route", file=sys.stderr)  # noqa: T201
    if answered:
        print(f"  FAIL: reachable from inside the lab: {answered}", file=sys.stderr)  # noqa: T201
    return 1 if routes or answered else 0


if __name__ == "__main__":
    raise SystemExit(main())
