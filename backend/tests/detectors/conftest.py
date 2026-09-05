"""Helpers for the detector suite: build event rows without a database; the labelled
fixtures are loaded through the same adapter ``make eval`` uses (normalise, then bound)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from pathlib import Path
from uuid import UUID, uuid4

from aegisnet.adapters.files.labelled import (  # noqa: F401 - re-exported for the suite
    EVALUATION_CLOCK,
    LabelledCase,
    case_dirs,
    load_case,
    row_from_normalized,
)
from aegisnet.domain.enums import EventType
from aegisnet.domain.ports import EventRow
from tests.conftest import REPO_ROOT

LABELLED = REPO_ROOT / "backend" / "tests" / "fixtures" / "labelled"
NOW = EVALUATION_CLOCK
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


def labelled_case_dirs() -> list[Path]:
    return case_dirs(LABELLED)
