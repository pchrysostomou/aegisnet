"""D-005 Outbound volume anomaly: an asset sends far more than its own rolling baseline
(PRD FR-4.5; specification in ``docs/detection-rules.md``). The baseline is precomputed
outside this rule and arrives on the window; without one the rule abstains."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Final

from aegisnet.domain.detectors.addresses import is_internal
from aegisnet.domain.detectors.model import (
    MAX_SAMPLES,
    Baseline,
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
METRIC: Final = "outbound_bytes_per_hour"
MIB: Final = 1024 * 1024


@dataclass(frozen=True, slots=True)
class VolumeAnomalyParams:
    """Fires when an hour's outbound bytes exceed both ``mean + stddev_multiplier * stddev``
    and ``p95_multiplier * p95`` of the asset's baseline, and at least ``min_bytes``.
    Abstains, never guesses, when the address has no baseline or fewer than
    ``min_samples`` sampled hours behind it."""

    stddev_multiplier: float = 3.0
    p95_multiplier: float = 2.0
    min_bytes: int = 50 * MIB
    min_samples: int = 24
    full_confidence_samples: int = 168

    def __post_init__(self) -> None:
        if not 0 < self.stddev_multiplier <= 100 or not 1 <= self.p95_multiplier <= 100:
            raise DetectionError("multipliers must be positive (p95 at least 1) and at most 100")
        if not 1 <= self.min_bytes <= 10**15:
            raise DetectionError("min_bytes must be between 1 and 1e15")
        if not 1 <= self.min_samples <= self.full_confidence_samples <= 100_000:
            raise DetectionError("1 <= min_samples <= full_confidence_samples <= 100000")


@dataclass
class _Tally:
    events: list[EventRow] = field(default_factory=list)
    bytes_out: int = 0
    destinations: set[str] = field(default_factory=set)


def _samples(events: list[EventRow]) -> tuple[EventSample, ...]:
    ordered = sorted(events, key=lambda e: -(e.bytes_toserver or 0))
    peak = ordered[0]
    chosen = [EventSample(events[0].id, SampleRole.first)]
    if len(events) > 1:
        chosen.append(EventSample(events[-1].id, SampleRole.last))
    taken = {s.event_id for s in chosen}
    if peak.id not in taken:
        chosen.append(EventSample(peak.id, SampleRole.peak))
        taken.add(peak.id)
    middle = [e for e in events if e.id not in taken]
    room = min(MAX_SAMPLES, 20) - len(chosen)
    if room > 0 and middle:
        step = max(1, len(middle) // room)
        chosen.extend(EventSample(e.id, SampleRole.sample) for e in middle[::step][:room])
    return tuple(chosen)


class VolumeAnomalyDetector:
    rule_id: Final = "D-005"
    name: Final = "Outbound volume anomaly"
    version: Final = 1
    base_severity: Final = 3
    window_seconds: Final = 3600
    description: Final = (
        "An asset's outbound bytes in one hour exceed its own rolling baseline by a wide "
        "margin (mean plus three standard deviations, and twice the 95th percentile, and an "
        "absolute floor). Abstains for addresses without a baseline or with too few sampled "
        "hours, so a new asset is never judged against nothing."
    )
    mitre_hint: Final = "T1041 Exfiltration Over C2 Channel"

    def __init__(self, params: VolumeAnomalyParams | None = None) -> None:
        self.params = params or VolumeAnomalyParams()

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

    def threshold(self, baseline: Baseline) -> int:
        params = self.params
        return int(
            max(
                baseline.mean + params.stddev_multiplier * baseline.stddev,
                params.p95_multiplier * baseline.p95,
                params.min_bytes,
            )
        )

    def run(self, window: EventWindow) -> list[DetectionResult]:
        if not window.baselines:
            return []
        params = self.params
        per_source: dict[str, _Tally] = {}
        for event in window.events:
            if event.event_type is not EventType.flow:
                continue
            if event.src_ip is None or event.dest_ip is None or not event.bytes_toserver:
                continue
            source = str(event.src_ip)
            if source not in window.baselines or is_internal(str(event.dest_ip)):
                continue
            tally = per_source.setdefault(source, _Tally())
            tally.events.append(event)
            tally.bytes_out += event.bytes_toserver
            tally.destinations.add(str(event.dest_ip))

        bucket = window_bucket(window.start, self.window_seconds)
        results: list[DetectionResult] = []
        for source in sorted(per_source):
            baseline = window.baselines[source]
            if baseline.metric != METRIC or baseline.sample_count < params.min_samples:
                continue
            tally = per_source[source]
            limit = self.threshold(baseline)
            if tally.bytes_out < limit:
                continue
            ratio = tally.bytes_out / limit
            confidence = 0.5 + 0.5 * min(
                1.0, baseline.sample_count / params.full_confidence_samples
            )
            results.append(
                DetectionResult(
                    rule_id=self.rule_id,
                    rule_version=self.version,
                    entity=Entity(EntityType.src_ip, source),
                    window_bucket=bucket,
                    first_seen=tally.events[0].event_time,
                    last_seen=tally.events[-1].event_time,
                    signal_strength=round(min(1.0, ratio / SIGNAL_SATURATION), 4),
                    confidence=round(confidence, 4),
                    event_count=len(tally.events),
                    evidence={
                        "bytes_out": tally.bytes_out,
                        "threshold_bytes": limit,
                        "ratio": round(ratio, 3),
                        "baseline_mean": round(baseline.mean, 1),
                        "baseline_stddev": round(baseline.stddev, 1),
                        "baseline_p95": round(baseline.p95, 1),
                        "baseline_samples": baseline.sample_count,
                        "baseline_window_days": baseline.window_days,
                        "flows": len(tally.events),
                        "distinct_destinations": len(tally.destinations),
                        "sample_destinations": sorted(tally.destinations)[:10],
                        "window_start": window.start,
                        "window_end": window.end,
                    },
                    samples=_samples(tally.events),
                )
            )
        return results
