"""D-002 Auth-failure burst: repeated authentication-failure indicators from one source
in a short span (PRD FR-4.2; specification in ``docs/detection-rules.md``)."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Final

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
SAMPLE_TARGETS: Final = 10
SAMPLE_SIGNATURE_IDS: Final = 10
SAMPLE_CATEGORIES: Final = 5
CATEGORY_CHARS: Final = 64
DEFAULT_PATTERNS: Final = (
    "brute",
    "login fail",
    "authentication fail",
    "auth fail",
    "invalid user",
    "failed password",
    "password guess",
    "privilege gain",
)


@dataclass(frozen=True, slots=True)
class AuthBurstParams:
    """``failures`` indicators from one source, of which the densest ``burst_seconds`` span
    must hold all ``failures``: a steady probe at one failure a minute reaches the count
    over ten minutes but never the burst, which is the guard the monitoring hard negative
    demands."""

    failures: int = 10
    burst_seconds: int = 120
    signature_patterns: tuple[str, ...] = DEFAULT_PATTERNS

    def __post_init__(self) -> None:
        if not 2 <= self.failures <= 100_000:
            raise DetectionError("failures must be between 2 and 100000")
        if not 1 <= self.burst_seconds <= 3600:
            raise DetectionError("burst_seconds must be between 1 and 3600")
        patterns = tuple(p.strip().lower() for p in self.signature_patterns)
        if not patterns or len(patterns) > 32 or any(not p or len(p) > 64 for p in patterns):
            raise DetectionError("signature_patterns: 1 to 32 entries of 1 to 64 characters")
        object.__setattr__(self, "signature_patterns", patterns)


def is_auth_failure(event: EventRow, patterns: tuple[str, ...]) -> bool:
    """A Suricata ``alert`` whose signature or category reads like an auth failure."""
    if event.event_type is not EventType.alert:
        return False
    text = f"{event.sig_signature or ''} {event.sig_category or ''}".lower()
    return any(pattern in text for pattern in patterns)


def densest_span(times: list[datetime], seconds: int) -> int:
    """The most events any ``seconds``-long span holds; ``times`` must be sorted."""
    best = 0
    start = 0
    for end, moment in enumerate(times):
        while (moment - times[start]).total_seconds() > seconds:
            start += 1
        best = max(best, end - start + 1)
    return best


@dataclass
class _Tally:
    events: list[EventRow] = field(default_factory=list)
    targets: set[str] = field(default_factory=set)
    signature_ids: set[int] = field(default_factory=set)
    categories: set[str] = field(default_factory=set)

    def add(self, event: EventRow) -> None:
        self.events.append(event)
        if event.dest_ip is not None:
            port = "" if event.dest_port is None else f":{event.dest_port}"
            self.targets.add(f"{event.dest_ip}{port}")
        if event.sig_signature_id is not None:
            self.signature_ids.add(event.sig_signature_id)
        if event.sig_category:
            self.categories.add(event.sig_category[:CATEGORY_CHARS])


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


class AuthBurstDetector:
    rule_id: Final = "D-002"
    name: Final = "Auth-failure burst"
    version: Final = 1
    base_severity: Final = 3
    window_seconds: Final = 600
    description: Final = (
        "One source produces many authentication-failure indicators (Suricata alerts whose "
        "signature or category reads like a brute-force or login failure) and the densest "
        "two-minute span holds the whole threshold, so a slow steady probe never trips it."
    )
    mitre_hint: Final = "T1110 Brute Force"

    def __init__(self, params: AuthBurstParams | None = None) -> None:
        self.params = params or AuthBurstParams()

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
        params = self.params
        per_source: dict[str, _Tally] = {}
        for event in window.events:
            if event.src_ip is None or not is_auth_failure(event, params.signature_patterns):
                continue
            per_source.setdefault(str(event.src_ip), _Tally()).add(event)

        bucket = window_bucket(window.start, self.window_seconds)
        results: list[DetectionResult] = []
        for source in sorted(per_source):
            tally = per_source[source]
            count = len(tally.events)
            if count < params.failures:
                continue
            burst = densest_span([e.event_time for e in tally.events], params.burst_seconds)
            if burst < params.failures:
                continue
            signal = min(1.0, burst / params.failures / SIGNAL_SATURATION)
            results.append(
                DetectionResult(
                    rule_id=self.rule_id,
                    rule_version=self.version,
                    entity=Entity(EntityType.src_ip, source),
                    window_bucket=bucket,
                    first_seen=tally.events[0].event_time,
                    last_seen=tally.events[-1].event_time,
                    signal_strength=round(signal, 4),
                    confidence=round(0.5 + 0.5 * burst / count, 4),
                    event_count=count,
                    evidence={
                        "failures": count,
                        "max_burst": burst,
                        "burst_seconds": params.burst_seconds,
                        "threshold": params.failures,
                        "distinct_targets": len(tally.targets),
                        "sample_targets": sorted(tally.targets)[:SAMPLE_TARGETS],
                        "signature_ids": sorted(tally.signature_ids)[:SAMPLE_SIGNATURE_IDS],
                        "sample_categories": sorted(tally.categories)[:SAMPLE_CATEGORIES],
                        "window_start": window.start,
                        "window_end": window.end,
                    },
                    samples=_samples(tally.events),
                )
            )
        return results
