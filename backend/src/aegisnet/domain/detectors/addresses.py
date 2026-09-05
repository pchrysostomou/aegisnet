"""What "internal" means to the rules that only care about outbound traffic (D-004, D-005).

Python's ``is_global`` treats the RFC 5737 documentation ranges the synthetic corpus uses
as non-global, so the rules keep their own explicit list: private, loopback, link-local,
carrier-grade NAT, unspecified, multicast and reserved space. Documentation and TEST-NET
addresses are, deliberately, "external" here.
"""

from __future__ import annotations

from ipaddress import ip_address, ip_network
from typing import Final

INTERNAL_NETWORKS: Final = tuple(
    ip_network(cidr)
    for cidr in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "::/128",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
    )
)


def is_internal(address: str) -> bool:
    parsed = ip_address(address)
    return any(parsed in network for network in INTERNAL_NETWORKS)
