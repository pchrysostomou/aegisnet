"""D-004 Periodic beaconing: low-jitter, regular-interval outbound connections from one
host to one destination (PRD FR-4.4; specification in ``docs/detection-rules.md``)."""

from __future__ import annotations

import math
from dataclasses import asdict, dataclass, field
from ipaddress import ip_network
from itertools import pairwise
from typing import Final

from aegisnet.domain.detectors.addresses import is_internal
from aegisnet.domain.detectors.model import (
    MAX_SAMPLES,
    DetectionError,
    DetectionResult,
    Entity,
    EventSample,
    EventWindow,
    RuleSpec,
    window_bucket,
)
from aegisnet.domain.enums import EntityType, EventType, SampleRole
from aegisnet.domain.ports import EventRow

SIGNAL_SATURATION: Final = 3.0
SAMPLE_DESTINATIONS: Final = 3
DEFAULT_ALLOWED_PORTS: Final = (53, 67, 68, 123, 1900, 5353)
DEFAULT_ALLOWED_APP_PROTOS: Final = ("dns", "dhcp", "ntp", "mdns")


@dataclass(frozen=True, slots=True)
class BeaconingParams:
    """A destination is a beacon when one host opened at least ``min_connections`` flows to
    it whose inter-arrival intervals average at least ``min_interval_seconds`` and vary by
    at most ``max_jitter`` (standard deviation over mean). Internal destinations never
    count unless ``include_internal`` is set: beaconing is outbound, and that is the guard
    a monitoring heartbeat to an internal collector demands."""

    min_connections: int = 10
    min_interval_seconds: float = 5.0
    max_jitter: float = 0.15
    allowed_ports: tuple[int, ...] = DEFAULT_ALLOWED_PORTS
    allowed_app_protos: tuple[str, ...] = DEFAULT_ALLOWED_APP_PROTOS
    allowed_destinations: tuple[str, ...] = ()
    include_internal: bool = False

    def __post_init__(self) -> None:
        if not 3 <= self.min_connections <= 100_000:
            raise DetectionError("min_connections must be between 3 and 100000")
        if not 0 < self.min_interval_seconds <= 86_400:
            raise DetectionError("min_interval_seconds must be between 0 and 86400")
        if not 0 < self.max_jitter <= 1:
            raise DetectionError("max_jitter must be between 0 and 1")
        if len(self.allowed_ports) > 256 or any(not 0 <= p <= 65535 for p in self.allowed_ports):
            raise DetectionError("allowed_ports: at most 256 ports in 0..65535")
        protos = tuple(p.strip().lower() for p in self.allowed_app_protos)
        if len(protos) > 64 or any(not p or len(p) > 32 for p in protos):
            raise DetectionError("allowed_app_protos: at most 64 names of 1 to 32 characters")
        object.__setattr__(self, "allowed_app_protos", protos)
        networks = []
        for text in self.allowed_destinations:
            try:
                networks.append(str(ip_network(text.strip(), strict=False)))
            except ValueError as error:
                raise DetectionError(
                    f"allowed_destinations: {text!r} is not an address or CIDR"
                ) from error
        if len(networks) > 256:
            raise DetectionError("allowed_destinations: at most 256 entries")
        object.__setattr__(self, "allowed_destinations", tuple(networks))


def interval_stats(seconds: list[float]) -> tuple[float, float]:
    """Mean and population standard deviation of inter-arrival intervals."""
    if not seconds:
        return 0.0, 0.0
    mean = sum(seconds) / len(seconds)
    variance = sum((s - mean) ** 2 for s in seconds) / len(seconds)
    return mean, math.sqrt(variance)


@dataclass
class _Destination:
    events: list[EventRow] = field(default_factory=list)
    bytes_out: int = 0


@dataclass(frozen=True, slots=True)
class _Beacon:
    destination: str
    connections: int
    mean_interval: float
    jitter: float
    bytes_out: int
    app_proto: str | None


def _samples(events: list[EventRow]) -> tuple[EventSample, ...]:
    chosen = [EventSample(events[0].id, SampleRole.first)]
    if len(events) > 1:
        chosen.append(EventSample(events[-1].id, SampleRole.last))
    taken = {s.event_id for s in chosen}
    middle = [e for e in events if e.id not in taken]
    room = min(MAX_SAMPLES, 20) - len(chosen)
    if room > 0 and middle:
        step = max(1, len(middle) // room)
        chosen.extend(EventSample(e.id, SampleRole.sample) for e in middle[::step][:room])
    return tuple(chosen)


class BeaconingDetector:
    rule_id: Final = "D-004"
    name: Final = "Periodic beaconing"
    version: Final = 1
    base_severity: Final = 4
    window_seconds: Final = 3600
    description: Final = (
        "One host opens outbound flows to one destination at a regular interval with little "
        "jitter. Internal destinations, well-known periodic protocols (DNS, DHCP, NTP, mDNS) "
        "and operator-listed destinations are excluded; irregular update checks never "
        "satisfy the jitter bound."
    )
    mitre_hint: Final = "T1071 Application Layer Protocol (command and control)"

    def __init__(self, params: BeaconingParams | None = None) -> None:
        self.params = params or BeaconingParams()
        self._allowed_networks = tuple(ip_network(n) for n in self.params.allowed_destinations)

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

    def _excluded(self, event: EventRow) -> bool:
        params = self.params
        assert event.dest_ip is not None
        if event.dest_port in params.allowed_ports:
            return True
        if event.app_proto and event.app_proto.lower() in params.allowed_app_protos:
            return True
        if not params.include_internal and is_internal(str(event.dest_ip)):
            return True
        return any(event.dest_ip in network for network in self._allowed_networks)

    def run(self, window: EventWindow) -> list[DetectionResult]:
        params = self.params
        per_source: dict[str, dict[str, _Destination]] = {}
        for event in window.events:
            if event.event_type is not EventType.flow:
                continue
            if event.src_ip is None or event.dest_ip is None or event.dest_port is None:
                continue
            if self._excluded(event):
                continue
            key = f"{event.dest_ip}:{event.dest_port}"
            slot = per_source.setdefault(str(event.src_ip), {}).setdefault(key, _Destination())
            slot.events.append(event)
            slot.bytes_out += event.bytes_toserver or 0

        bucket = window_bucket(window.start, self.window_seconds)
        results: list[DetectionResult] = []
        for source in sorted(per_source):
            beacons: list[tuple[_Beacon, list[EventRow]]] = []
            for destination, slot in per_source[source].items():
                if len(slot.events) < params.min_connections:
                    continue
                times = [e.event_time for e in slot.events]
                intervals = [(b - a).total_seconds() for a, b in pairwise(times)]
                mean, stddev = interval_stats(intervals)
                if mean < params.min_interval_seconds:
                    continue
                jitter = stddev / mean
                if jitter > params.max_jitter:
                    continue
                beacons.append(
                    (
                        _Beacon(
                            destination=destination,
                            connections=len(slot.events),
                            mean_interval=round(mean, 2),
                            jitter=round(jitter, 4),
                            bytes_out=slot.bytes_out,
                            app_proto=slot.events[0].app_proto,
                        ),
                        slot.events,
                    )
                )
            if not beacons:
                continue
            beacons.sort(
                key=lambda item: (item[0].jitter, -item[0].connections, item[0].destination)
            )
            best, events = beacons[0]
            all_events = sorted(
                (e for _, evs in beacons for e in evs), key=lambda e: (e.event_time, e.id.int)
            )
            signal = min(1.0, best.connections / params.min_connections / SIGNAL_SATURATION)
            confidence = max(0.5, min(1.0, 1.0 - best.jitter / params.max_jitter * 0.5))
            results.append(
                DetectionResult(
                    rule_id=self.rule_id,
                    rule_version=self.version,
                    entity=Entity(EntityType.src_ip, source),
                    window_bucket=bucket,
                    first_seen=all_events[0].event_time,
                    last_seen=all_events[-1].event_time,
                    signal_strength=round(signal, 4),
                    confidence=round(confidence, 4),
                    event_count=len(all_events),
                    evidence={
                        "destination": best.destination,
                        "connections": best.connections,
                        "mean_interval_seconds": best.mean_interval,
                        "jitter": best.jitter,
                        "bytes_out": best.bytes_out,
                        "app_proto": best.app_proto or "",
                        "beaconing_destinations": [
                            b.destination for b, _ in beacons[:SAMPLE_DESTINATIONS]
                        ],
                        "threshold_connections": params.min_connections,
                        "max_jitter": params.max_jitter,
                        "window_start": window.start,
                        "window_end": window.end,
                    },
                    samples=_samples(events),
                )
            )
        return results
