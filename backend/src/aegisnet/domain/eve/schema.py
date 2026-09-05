"""Pydantic schema for Suricata EVE JSON records.

Field names follow the EVE JSON format reference
(https://docs.suricata.io/en/latest/output/eve/eve-json-format.html). Only the fields the
project promotes or relies on are typed; every model allows extra keys, because Suricata
emits many optional fields and refusing an unknown key would reject real telemetry. The
sanitiser has already stripped control characters and capped string lengths by the time a
record reaches this schema, and the structural limits have already been enforced, so
``extra="allow"`` cannot admit unbounded content.

Two fields are required: ``timestamp`` and ``event_type``. Everything else is optional and
validated only when present.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any, Final

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, field_validator

_TZ_WITHOUT_COLON: Final = re.compile(r"([+-]\d{2})(\d{2})$")

MAX_EVENT_TYPE_CHARS: Final = 64
MAX_PORT: Final = 65535


class _SubObject(BaseModel):
    model_config = ConfigDict(extra="allow", frozen=True)


class AlertInfo(_SubObject):
    """Suricata's own signature hit: *evidence*, not an AegisNet alert (ADR-003)."""

    action: str | None = None
    gid: int | None = Field(default=None, ge=0)
    signature_id: int | None = Field(default=None, ge=0)
    rev: int | None = Field(default=None, ge=0)
    signature: str | None = None
    category: str | None = None
    severity: int | None = Field(default=None, ge=0)


class DnsQuery(_SubObject):
    rrname: str | None = None
    rrtype: str | None = None


class DnsInfo(_SubObject):
    version: int | None = None
    type: str | None = None
    id: int | None = Field(default=None, ge=0)
    rrname: str | None = None
    rrtype: str | None = None
    rcode: str | None = None
    tx_id: int | None = Field(default=None, ge=0)
    queries: list[DnsQuery] | None = None
    answers: list[dict[str, Any]] | None = None


class HttpInfo(_SubObject):
    hostname: str | None = None
    url: str | None = None
    http_method: str | None = None
    protocol: str | None = None
    status: int | None = Field(default=None, ge=0)
    length: int | None = Field(default=None, ge=0)
    http_user_agent: str | None = None
    http_content_type: str | None = None


class FlowInfo(_SubObject):
    pkts_toserver: int | None = Field(default=None, ge=0)
    pkts_toclient: int | None = Field(default=None, ge=0)
    bytes_toserver: int | None = Field(default=None, ge=0)
    bytes_toclient: int | None = Field(default=None, ge=0)
    # Kept as text and parsed separately (``parse_suricata_time`` below) rather than typed as
    # a datetime: a malformed ``start`` must not turn an otherwise good flow record into a
    # reject, and the normaliser falls back to the record's own timestamp when it cannot read
    # this (ADR-022).
    start: str | None = None
    end: str | None = None
    age: int | None = Field(default=None, ge=0)
    state: str | None = None
    reason: str | None = None
    alerted: bool | None = None


class TlsInfo(_SubObject):
    sni: str | None = None
    subject: str | None = None
    issuerdn: str | None = None
    version: str | None = None
    fingerprint: str | None = None


class FileInfo(_SubObject):
    filename: str | None = None
    magic: str | None = None
    state: str | None = None
    size: int | None = Field(default=None, ge=0)
    sha256: str | None = None
    stored: bool | None = None


class AnomalyInfo(_SubObject):
    type: str | None = None
    event: str | None = None
    layer: str | None = None
    code: int | None = None


class SshInfo(_SubObject):
    client: dict[str, Any] | None = None
    server: dict[str, Any] | None = None


class EveRecord(BaseModel):
    model_config = ConfigDict(extra="allow", frozen=True)

    timestamp: datetime
    event_type: str = Field(min_length=1, max_length=MAX_EVENT_TYPE_CHARS)
    flow_id: int | None = Field(default=None, ge=0)
    in_iface: str | None = None
    src_ip: IPvAnyAddress | None = None
    src_port: int | None = Field(default=None, ge=0, le=MAX_PORT)
    dest_ip: IPvAnyAddress | None = None
    dest_port: int | None = Field(default=None, ge=0, le=MAX_PORT)
    proto: str | None = None
    app_proto: str | None = None
    tx_id: int | None = Field(default=None, ge=0)
    pcap_cnt: int | None = Field(default=None, ge=0)
    community_id: str | None = None

    alert: AlertInfo | None = None
    dns: DnsInfo | None = None
    http: HttpInfo | None = None
    flow: FlowInfo | None = None
    tls: TlsInfo | None = None
    fileinfo: FileInfo | None = None
    anomaly: AnomalyInfo | None = None
    ssh: SshInfo | None = None

    @field_validator("timestamp", mode="before")
    @classmethod
    def _accept_suricata_offset(cls, value: object) -> object:
        """Suricata writes ``+0000``; ISO 8601 parsers want ``+00:00``."""
        if isinstance(value, str):
            return _TZ_WITHOUT_COLON.sub(r"\1:\2", value.strip())
        return value

    @field_validator("timestamp")
    @classmethod
    def _require_offset_and_normalise_to_utc(cls, value: datetime) -> datetime:
        """A naive timestamp is refused rather than guessed (T-1.7)."""
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must carry a UTC offset")
        return value.astimezone(UTC)


def parse_suricata_time(value: str | None) -> datetime | None:
    """A Suricata timestamp string as an aware UTC instant, or ``None`` when it is absent,
    malformed or naive. Used for the sub-second fields Suricata writes as text — ``flow.start``
    above all — which are read best-effort rather than validated into existence."""
    if value is None:
        return None
    text = _TZ_WITHOUT_COLON.sub(r"\1:\2", value.strip())
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed.astimezone(UTC)
