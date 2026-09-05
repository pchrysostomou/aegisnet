"""D-001 Port scan: one source touching many distinct destination ports or hosts in a
short window (PRD FR-4.1; full specification in ``docs/detection-rules.md``)."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Final

from aegisnet.domain.detectors.model import (
    MAX_SAMPLES,
    DetectionError,
    DetectionResult,
    Entity,
    EntityType,
    EventSample,
    EventWindow,
    RuleSpec,
    SampleRole,
    window_bucket,
)
from aegisnet.domain.enums import EventType
from aegisnet.domain.ports import EventRow

SAMPLE_PORTS: Final = 20
SAMPLE_HOSTS: Final = 10
SIGNAL_SATURATION: Final = 3.0
"""Signal strength reaches 1.0 at three times the threshold."""


@dataclass(frozen=True, slots=True)
class PortScanParams:
    """Thresholds per source address within one window. A single address on a single port
    can never trip the rule however many connections it opens: the unit is the distinct
    ``(host, port)`` target, which is what separates a scan from a busy client."""

    distinct_ports: int = 20
    distinct_hosts: int = 15
    min_flows: int = 20

    def __post_init__(self) -> None:
        for name, value in asdict(self).items():
            if not 2 <= value <= 100_000:
                raise DetectionError(f"{name} must be between 2 and 100000")


@dataclass
class _Tally:
    flows: int = 0
    unanswered: int = 0
    ports: set[int] = field(default_factory=set)
    hosts: set[str] = field(default_factory=set)
    targets: set[tuple[str, int]] = field(default_factory=set)
    first: EventRow | None = None
    last: EventRow | None = None
    ids: list[EventRow] = field(default_factory=list)

    def add(self, event: EventRow) -> None:
        assert event.dest_ip is not None and event.dest_port is not None
        host = str(event.dest_ip)
        self.flows += 1
        if not event.pkts_toclient:
            self.unanswered += 1
        self.ports.add(event.dest_port)
        self.hosts.add(host)
        self.targets.add((host, event.dest_port))
        if self.first is None:
            self.first = event
        self.last = event
        self.ids.append(event)


def _samples(tally: _Tally) -> tuple[EventSample, ...]:
    assert tally.first is not None and tally.last is not None
    chosen: list[EventSample] = [EventSample(tally.first.id, SampleRole.first)]
    if tally.last.id != tally.first.id:
        chosen.append(EventSample(tally.last.id, SampleRole.last))
    taken = {s.event_id for s in chosen}
    room = min(MAX_SAMPLES, 20) - len(chosen)
    middle = [e for e in tally.ids if e.id not in taken]
    if room > 0 and middle:
        step = max(1, len(middle) // room)
        for event in middle[::step][:room]:
            chosen.append(EventSample(event.id, SampleRole.sample))
    return tuple(chosen)


class PortScanDetector:
    rule_id: Final = "D-001"
    name: Final = "Port scan"
    version: Final = 1
    base_severity: Final = 3
    window_seconds: Final = 600
    description: Final = (
        "One source opens flows to many distinct destination ports (vertical) or many "
        "distinct destination hosts (horizontal) inside a ten-minute window. Counts "
        "distinct (host, port) targets, never connections, so a busy client on one port "
        "cannot trip it; unanswered flows raise confidence."
    )
    mitre_hint: Final = "T1046 Network Service Discovery"

    def __init__(self, params: PortScanParams | None = None) -> None:
        self.params = params or PortScanParams()

    @property
    def spec(self) -> RuleSpec:
        return RuleSpec(
            rule_id=self.rule_id,
            name=self.name,
            version=self.version,
            base_severity=self.base_severity,
            window_seconds=self.window_seconds,
            params=asdict(self.params),
            description=self.description,
            mitre_hint=self.mitre_hint,
        )

    def run(self, window: EventWindow) -> list[DetectionResult]:
        per_source: dict[str, _Tally] = {}
        for event in window.events:
            if event.event_type is not EventType.flow:
                continue
            if event.src_ip is None or event.dest_ip is None or event.dest_port is None:
                continue
            per_source.setdefault(str(event.src_ip), _Tally()).add(event)

        params = self.params
        bucket = window_bucket(window.start, self.window_seconds)
        results: list[DetectionResult] = []
        for source in sorted(per_source):
            tally = per_source[source]
            if tally.flows < params.min_flows:
                continue
            ports, hosts = len(tally.ports), len(tally.hosts)
            if ports < params.distinct_ports and hosts < params.distinct_hosts:
                continue
            ratio = max(ports / params.distinct_ports, hosts / params.distinct_hosts)
            signal = min(1.0, ratio / SIGNAL_SATURATION)
            unanswered_share = tally.unanswered / tally.flows
            assert tally.first is not None and tally.last is not None
            results.append(
                DetectionResult(
                    rule_id=self.rule_id,
                    rule_version=self.version,
                    entity=Entity(EntityType.src_ip, source),
                    window_bucket=bucket,
                    first_seen=tally.first.event_time,
                    last_seen=tally.last.event_time,
                    signal_strength=round(signal, 4),
                    confidence=round(0.5 + 0.5 * unanswered_share, 4),
                    event_count=tally.flows,
                    evidence={
                        "distinct_dest_ports": ports,
                        "distinct_dest_hosts": hosts,
                        "distinct_targets": len(tally.targets),
                        "flows": tally.flows,
                        "unanswered_flows": tally.unanswered,
                        "threshold_ports": params.distinct_ports,
                        "threshold_hosts": params.distinct_hosts,
                        "sample_dest_ports": sorted(tally.ports)[:SAMPLE_PORTS],
                        "sample_dest_hosts": sorted(tally.hosts)[:SAMPLE_HOSTS],
                        "window_start": window.start,
                        "window_end": window.end,
                    },
                    samples=_samples(tally),
                )
            )
        return results
