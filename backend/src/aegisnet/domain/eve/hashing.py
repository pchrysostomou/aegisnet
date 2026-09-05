"""Canonical ``event_hash`` (ADR-005, ADR-013).

``sha256`` over a versioned, canonical JSON rendering of a documented subset of the
record: the common fields that identify the observation, plus the complete sanitised
event-type object. Re-ingesting the same file yields the same digests, which is what makes
ingest idempotent; the digest is stored in ``events.event_hash`` under a UNIQUE index.

The version prefix means a future change to the subset or the sanitiser produces new
digests rather than silently colliding or silently duplicating.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from datetime import UTC
from typing import Any, Final

from aegisnet.domain.eve.schema import EveRecord

HASH_VERSION: Final = 1
HASH_BYTES: Final = 32

_PREFIX: Final = f"aegisnet-event-hash-v{HASH_VERSION}\n".encode()

TYPE_OBJECT_KEYS: Final = frozenset(
    {"alert", "dns", "http", "flow", "tls", "fileinfo", "anomaly", "ssh"}
)
"""Sub-objects included whole. ``flow`` also appears as metadata on other event types."""


def hash_material(record: EveRecord, sanitized: Mapping[str, Any]) -> dict[str, Any]:
    """The subset that is hashed, built from validated values so equivalent spellings
    (``+0000`` vs ``+00:00``, leading zeros in an address) canonicalise identically."""
    material: dict[str, Any] = {
        "timestamp": record.timestamp.astimezone(UTC).isoformat(timespec="microseconds"),
        "event_type": record.event_type,
    }
    common: dict[str, Any] = {
        "flow_id": record.flow_id,
        "in_iface": record.in_iface,
        "src_ip": None if record.src_ip is None else str(record.src_ip),
        "src_port": record.src_port,
        "dest_ip": None if record.dest_ip is None else str(record.dest_ip),
        "dest_port": record.dest_port,
        "proto": record.proto,
        "app_proto": record.app_proto,
        "tx_id": record.tx_id,
        "pcap_cnt": record.pcap_cnt,
        "community_id": record.community_id,
    }
    material.update({key: value for key, value in common.items() if value is not None})
    for key in sorted(TYPE_OBJECT_KEYS):
        sub = sanitized.get(key)
        if isinstance(sub, dict):
            material[key] = sub
    return material


def event_hash(material: Mapping[str, Any]) -> bytes:
    canonical = json.dumps(
        material, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str
    )
    return hashlib.sha256(_PREFIX + canonical.encode("utf-8")).digest()
