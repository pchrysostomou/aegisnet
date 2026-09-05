"""Labelled detector cases and the benign corpus, read from disk the way a window loader
hands events to a detector: normalised through the EVE parser, then bounded (ADR-020).

The fixtures' timestamps are fixed, so normalisation's freshness check runs against a
fixed instant rather than the wall clock; otherwise the same files would start being
rejected as "too old" one day and the evaluation would silently change.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import NAMESPACE_URL, UUID, uuid5

import yaml

from aegisnet.domain.detectors import Baseline, Entity, EventWindow
from aegisnet.domain.detectors.evaluation import Expectation
from aegisnet.domain.enums import EntityType
from aegisnet.domain.eve.normalizer import normalize_lines
from aegisnet.domain.models import NormalizedEvent
from aegisnet.domain.ports import EventRow

EVALUATION_CLOCK = datetime(2026, 9, 5, 12, 0, tzinfo=UTC)
EVALUATION_BATCH = UUID(int=1)


class LabelledCaseError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class LabelledCase:
    directory: Path
    labels: dict[str, Any]
    window: EventWindow

    @property
    def case_id(self) -> str:
        return str(self.labels["case_id"])

    @property
    def rule_id(self) -> str:
        return str(self.labels["rule_id"])

    @property
    def kind(self) -> str:
        return self.directory.parent.name

    def expectation(self) -> Expectation:
        if self.labels["expected"] == "no_detection":
            return Expectation(self.rule_id, self.case_id, "negative", None, None)
        if self.labels["expected"] != "detection":
            raise LabelledCaseError(f"{self.case_id}: unknown expectation")
        entity = self.labels["expected_entity"]
        return Expectation(
            self.rule_id,
            self.case_id,
            "positive",
            Entity(EntityType(str(entity["type"])), str(entity["value"])),
            int(self.labels["expected_min_severity"]),
        )


def row_from_normalized(event: NormalizedEvent, *, batch_id: UUID = EVALUATION_BATCH) -> EventRow:
    """What the SQL store would hand back, with a deterministic id from the event hash."""
    return EventRow(
        id=uuid5(NAMESPACE_URL, event.event_hash.hex()),
        batch_id=batch_id,
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


def _moment(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def _rows(lines: list[str], *, now: datetime, where: str) -> tuple[list[EventRow], int]:
    rows: list[EventRow] = []
    rejected = 0
    for number, outcome in normalize_lines(lines, now=now):
        if isinstance(outcome, NormalizedEvent):
            rows.append(row_from_normalized(outcome))
        else:
            rejected += 1
            if where:
                raise LabelledCaseError(f"{where} line {number}: {outcome}")
    return rows, rejected


def load_case(directory: Path, *, now: datetime = EVALUATION_CLOCK) -> LabelledCase:
    """One case directory (``labels.yml`` + ``events.ndjson``); a line the normaliser
    rejects is an error, a labelled case must be clean input."""
    labels = yaml.safe_load((directory / "labels.yml").read_text(encoding="utf-8"))
    lines = (directory / "events.ndjson").read_text(encoding="utf-8").splitlines()
    rows, _ = _rows(lines, now=now, where=directory.name)
    baselines = {
        str(b["address"]): Baseline(
            metric=str(b["metric"]),
            window_days=int(b["window_days"]),
            mean=float(b["mean"]),
            stddev=float(b["stddev"]),
            p95=float(b["p95"]),
            sample_count=int(b["sample_count"]),
        )
        for b in labels.get("baselines", [])
    }
    window = EventWindow(
        _moment(labels["window"]["start"]),
        _moment(labels["window"]["end"]),
        tuple(rows),
        baselines=baselines,
    )
    return LabelledCase(directory, labels, window)


def case_dirs(root: Path) -> list[Path]:
    """Every ``<rule>/<positive|negative>/<case>/`` under ``root``, sorted."""
    return sorted(p.parent for p in root.glob("*/*/*/labels.yml"))


def load_corpus(
    path: Path, *, now: datetime = EVALUATION_CLOCK
) -> tuple[tuple[EventRow, ...], int]:
    """A whole NDJSON corpus as sorted rows plus the number of lines the normaliser
    rejected (a corpus may legitimately carry a few)."""
    lines = path.read_text(encoding="utf-8").splitlines()
    rows, rejected = _rows(lines, now=now, where="")
    rows.sort(key=lambda r: (r.event_time, r.id.int))
    return tuple(rows), rejected
