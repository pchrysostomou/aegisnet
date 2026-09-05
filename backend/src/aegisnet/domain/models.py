"""Pure value objects shared across the domain.

Frozen dataclasses only. No ORM, no I/O, no framework types. The ORM row for
``NormalizedEvent`` is ``aegisnet.adapters.db.models.Event``; the adapter copies fields
across, the domain never imports it.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
from typing import Any

from aegisnet.domain.enums import EventType, RejectReason

IPAddress = IPv4Address | IPv6Address


@dataclass(frozen=True, slots=True)
class NormalizedEvent:
    """One EVE record after validation, sanitisation and promotion (ADR-001, ADR-005).

    ``payload`` is the complete sanitised record. Promoted columns are bounded copies of
    the fields detectors query, so drill-down never needs a second source (ADR-013). The
    dict is shared, not copied; treat it as read-only.
    """

    event_hash: bytes
    event_time: datetime
    event_type: EventType
    flow_id: int | None
    src_ip: IPAddress | None
    dest_ip: IPAddress | None
    src_port: int | None
    dest_port: int | None
    proto: str | None
    app_proto: str | None
    bytes_toserver: int | None
    bytes_toclient: int | None
    pkts_toserver: int | None
    pkts_toclient: int | None
    dns_query: str | None
    dns_rrtype: str | None
    dns_rcode: str | None
    http_host: str | None
    http_url_path: str | None
    sig_signature: str | None
    sig_category: str | None
    sig_signature_id: int | None
    sig_severity: int | None
    payload: dict[str, Any]


@dataclass(frozen=True, slots=True)
class Reject:
    """Why one line was not stored. Mirrors an ``ingest_rejects`` row.

    ``detail`` is built from error kinds and field paths, never from input values, and
    ``raw_excerpt`` is the sanitised, capped head of the line for debugging only.
    """

    reason: RejectReason
    detail: str
    raw_excerpt: str | None
