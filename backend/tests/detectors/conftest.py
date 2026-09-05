"""Helpers for the detector suite: build event rows without a database and load the
labelled fixtures the way a window loader would (normalise, then bound)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from pathlib import Path
from typing import Any
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

import yaml

from aegisnet.domain.detectors import EventWindow
from aegisnet.domain.enums import EventType
from aegisnet.domain.eve.normalizer import normalize_lines
from aegisnet.domain.models import NormalizedEvent
from aegisnet.domain.ports import EventRow
from tests.conftest import REPO_ROOT

LABELLED = REPO_ROOT / "backend" / "tests" / "fixtures" / "labelled"
NOW = datetime(2026, 9, 5, 12, 0, tzinfo=UTC)
WINDOW_START = datetime(2026, 9, 1, 10, 0, tzinfo=UTC)
WINDOW_END = WINDOW_START + timedelta(minutes=10)
BATCH = UUID(int=1)


def flow_row(
    when: datetime,
    src: str,
    dst: str,
    dport: int,
    *,
    answered: bool = False,
    event_type: EventType = EventType.flow,
    event_id: UUID | None = None,
) -> EventRow:
    return EventRow(
        id=event_id or uuid4(),
        batch_id=BATCH,
        event_time=when,
        ingested_at=when,
        event_type=event_type,
        flow_id=1,
        src_ip=ip_address(src),
        dest_ip=ip_address(dst),
        src_port=40000,
        dest_port=dport,
        proto="TCP",
        app_proto=None,
        bytes_toserver=60,
        bytes_toclient=800 if answered else 0,
        pkts_toserver=1,
        pkts_toclient=6 if answered else 0,
        dns_query=None,
        dns_rrtype=None,
        dns_rcode=None,
        http_host=None,
        http_url_path=None,
        sig_signature=None,
        sig_category=None,
        sig_signature_id=None,
        sig_severity=None,
        payload=None,
    )


def row_from_normalized(event: NormalizedEvent) -> EventRow:
    """What the SQL store would hand back, with a deterministic id from the event hash."""
    return EventRow(
        id=uuid5(NAMESPACE_URL, event.event_hash.hex()),
        batch_id=BATCH,
        event_time=event.event_time,
        ingested_at=event.event_time,
        event_type=event.event_type,
        flow_id=event.flow_id,
        src_ip=event.src_ip,
        dest_ip=event.dest_ip,
        src_port=event.src_port,
        dest_port=event.dest_port,
        proto=event.proto,
        app_proto=event.app_proto,
        bytes_toserver=event.bytes_toserver,
        bytes_toclient=event.bytes_toclient,
        pkts_toserver=event.pkts_toserver,
        pkts_toclient=event.pkts_toclient,
        dns_query=event.dns_query,
        dns_rrtype=event.dns_rrtype,
        dns_rcode=event.dns_rcode,
        http_host=event.http_host,
        http_url_path=event.http_url_path,
        sig_signature=event.sig_signature,
        sig_category=event.sig_category,
        sig_signature_id=event.sig_signature_id,
        sig_severity=event.sig_severity,
        payload=None,
    )


@dataclass(frozen=True)
class LabelledCase:
    directory: Path
    labels: dict[str, Any]
    window: EventWindow

    @property
    def case_id(self) -> str:
        return str(self.labels["case_id"])


def _moment(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def load_case(directory: Path) -> LabelledCase:
    labels = yaml.safe_load((directory / "labels.yml").read_text(encoding="utf-8"))
    lines = (directory / "events.ndjson").read_text(encoding="utf-8").splitlines()
    rows: list[EventRow] = []
    for number, outcome in normalize_lines(lines, now=NOW):
        assert isinstance(outcome, NormalizedEvent), f"{directory.name} line {number}: {outcome}"
        rows.append(row_from_normalized(outcome))
    window = EventWindow(
        _moment(labels["window"]["start"]), _moment(labels["window"]["end"]), tuple(rows)
    )
    return LabelledCase(directory, labels, window)


def labelled_case_dirs() -> list[Path]:
    return sorted(p.parent for p in LABELLED.glob("*/*/*/labels.yml"))
