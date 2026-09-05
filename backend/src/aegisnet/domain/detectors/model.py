"""Detection value objects: the window a detector sees, what it emits, and the bounds that
keep both honest (FR-4, FR-5.1, FR-5.3, T-1.7)."""

from __future__ import annotations

import math
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Any, Final, Protocol
from uuid import UUID

from aegisnet.domain.enums import EntityType, SampleRole

__all__ = [
    "EntityType",
    "SampleRole",
    "DetectionError",
    "Entity",
    "EventWindow",
    "Baseline",
    "EventSample",
    "DetectionResult",
    "RuleSpec",
    "Detector",
    "window_bucket",
    "bounded_evidence",
    "MAX_WINDOW",
    "MAX_WINDOW_EVENTS",
    "MAX_EVIDENCE_KEYS",
    "MAX_EVIDENCE_ITEMS",
    "MAX_EVIDENCE_CHARS",
    "MAX_SAMPLES",
]
from aegisnet.domain.ports import EventRow

MAX_WINDOW: Final = timedelta(hours=24)
"""The largest span a detector is ever handed; longer sweeps are split by the caller."""
MAX_WINDOW_EVENTS: Final = 200_000
"""Event cap per window (delivery plan M2: DoS via pathological windows)."""
MAX_EVIDENCE_KEYS: Final = 32
MAX_EVIDENCE_ITEMS: Final = 50
MAX_EVIDENCE_CHARS: Final = 128
MAX_SAMPLES: Final = 50
RULE_ID: Final = re.compile(r"^D-\d{3}$")
FORBIDDEN_EVIDENCE_KEYS: Final = frozenset({"raw", "line", "raw_line", "raw_excerpt", "payload"})
"""Evidence is derived and bounded; a raw log line never travels in it (FR-5.3)."""
_CONTROL: Final = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


class DetectionError(ValueError):
    """A window or a result that violates the bounds this package promises."""


@dataclass(frozen=True, slots=True)
class Entity:
    """The correlation key an alert will carry (``alerts.entity_type`` / ``entity_value``)."""

    type: EntityType
    value: str

    def __post_init__(self) -> None:
        if not self.value or len(self.value) > 253 or self.value != self.value.strip():
            raise DetectionError("entity value must be 1 to 253 characters with no padding")
        if _CONTROL.search(self.value):
            raise DetectionError("entity value must not contain control characters")


def _aware(moment: datetime, name: str) -> datetime:
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise DetectionError(f"{name} must carry a UTC offset")
    return moment


@dataclass(frozen=True, slots=True)
class Baseline:
    """Rolling statistics for one address's asset (``asset_baselines``), precomputed by the
    baseline job and handed to the window so a rule that needs history stays pure."""

    metric: str
    window_days: int
    mean: float
    stddev: float
    p95: float
    sample_count: int

    def __post_init__(self) -> None:
        if self.window_days < 1 or self.sample_count < 0:
            raise DetectionError("a baseline needs a positive window and a sample count")
        for name in ("mean", "stddev", "p95"):
            value = getattr(self, name)
            if not (math.isfinite(value) and value >= 0):
                raise DetectionError(f"baseline {name} must be a finite non-negative number")


@dataclass(frozen=True, slots=True)
class EventWindow:
    """A bounded, ordered slice of events with the interval it was loaded for.

    ``events`` are sorted by ``(event_time, id)`` and every one lies in ``[start, end)``;
    the loader, not the detector, decides what belongs to a window. ``event_time`` is the
    data's own clock: a forged timestamp can move an event between windows but can never
    widen one (T-1.7). ``baselines`` maps an address to its asset's precomputed statistics
    for the rules that compare against history (D-005); it is empty unless the sweep
    loaded any.
    """

    start: datetime
    end: datetime
    events: tuple[EventRow, ...]
    baselines: Mapping[str, Baseline] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _aware(self.start, "window start")
        _aware(self.end, "window end")
        for address in self.baselines:
            try:
                ip_address(address)
            except ValueError as error:
                raise DetectionError("baselines are keyed by IP address") from error
        if self.end <= self.start:
            raise DetectionError("window end must be after its start")
        if self.end - self.start > MAX_WINDOW:
            raise DetectionError(f"window spans more than {MAX_WINDOW}")
        if len(self.events) > MAX_WINDOW_EVENTS:
            raise DetectionError(f"window holds more than {MAX_WINDOW_EVENTS} events")
        for event in self.events:
            _aware(event.event_time, "event_time")
            if not self.start <= event.event_time < self.end:
                raise DetectionError("every event must lie inside the window")
        ordered = tuple(sorted(self.events, key=lambda e: (e.event_time, e.id.int)))
        object.__setattr__(self, "events", ordered)

    @property
    def span(self) -> timedelta:
        return self.end - self.start


def window_bucket(start: datetime, window_seconds: int) -> datetime:
    """Floor ``start`` onto the rule's window grid, so a re-sweep over the same interval
    produces the same ``dedup_key`` (data model: ``rule_id:entity:window_bucket``)."""
    if window_seconds <= 0:
        raise DetectionError("window_seconds must be positive")
    _aware(start, "window start")
    epoch = int(start.timestamp())
    return datetime.fromtimestamp(epoch - epoch % window_seconds, tz=UTC)


def _scalar(value: Any) -> Any:
    if value is None or isinstance(value, bool | int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise DetectionError("evidence numbers must be finite")
        return value
    if isinstance(value, datetime):
        return _aware(value, "evidence timestamp").isoformat()
    if isinstance(value, UUID | IPv4Address | IPv6Address):
        return str(value)
    if isinstance(value, str):
        if len(value) > MAX_EVIDENCE_CHARS or _CONTROL.search(value):
            raise DetectionError("evidence strings are short identifiers, never log text")
        return value
    raise DetectionError(f"unsupported evidence value type {type(value).__name__}")


def bounded_evidence(detail: Mapping[str, Any]) -> dict[str, Any]:
    """Only scalars and short lists of scalars, under fixed caps; never a raw line."""
    cleaned: dict[str, Any] = {}
    for key, value in detail.items():
        name = str(key)
        if not name or len(name) > 64 or name in FORBIDDEN_EVIDENCE_KEYS:
            raise DetectionError(f"evidence key {name!r} is not allowed")
        if len(cleaned) >= MAX_EVIDENCE_KEYS:
            raise DetectionError(f"evidence has more than {MAX_EVIDENCE_KEYS} keys")
        if isinstance(value, list | tuple | set | frozenset):
            items = list(value)
            if len(items) > MAX_EVIDENCE_ITEMS:
                raise DetectionError(f"evidence lists hold at most {MAX_EVIDENCE_ITEMS} items")
            cleaned[name] = [_scalar(item) for item in items]
        else:
            cleaned[name] = _scalar(value)
    return cleaned


@dataclass(frozen=True, slots=True)
class EventSample:
    event_id: UUID
    role: SampleRole


@dataclass(frozen=True, slots=True)
class DetectionResult:
    """What a detector emits for one entity in one window (FR-5.1).

    ``signal_strength`` says how far past its threshold the rule went (0..1) and feeds the
    severity formula; ``confidence`` says how sure the rule is that the pattern is what it
    looks like (0..1). ``event_count`` is the total, ``samples`` a capped selection.
    """

    rule_id: str
    rule_version: int
    entity: Entity
    window_bucket: datetime
    first_seen: datetime
    last_seen: datetime
    signal_strength: float
    confidence: float
    event_count: int
    evidence: dict[str, Any]
    samples: tuple[EventSample, ...]

    def __post_init__(self) -> None:
        if not RULE_ID.match(self.rule_id):
            raise DetectionError("rule_id must look like D-001")
        if self.rule_version < 1:
            raise DetectionError("rule_version starts at 1")
        _aware(self.window_bucket, "window_bucket")
        if _aware(self.first_seen, "first_seen") > _aware(self.last_seen, "last_seen"):
            raise DetectionError("first_seen must not be after last_seen")
        for name in ("signal_strength", "confidence"):
            value = getattr(self, name)
            if not (isinstance(value, int | float) and math.isfinite(value) and 0 <= value <= 1):
                raise DetectionError(f"{name} must be between 0 and 1")
        if self.event_count < 1:
            raise DetectionError("a result needs at least one contributing event")
        if len(self.samples) > MAX_SAMPLES:
            raise DetectionError(f"at most {MAX_SAMPLES} sampled events")
        if len({s.event_id for s in self.samples}) != len(self.samples):
            raise DetectionError("sampled event ids must be unique")
        if len(self.samples) > self.event_count:
            raise DetectionError("more samples than contributing events")
        object.__setattr__(self, "evidence", bounded_evidence(self.evidence))

    @property
    def dedup_key(self) -> str:
        return (
            f"{self.rule_id}:{self.entity.type.value}={self.entity.value}:"
            f"{self.window_bucket.isoformat()}"
        )


@dataclass(frozen=True, slots=True)
class RuleSpec:
    """The registry row a rule is reproducible against (``detection_rules``)."""

    rule_id: str
    name: str
    version: int
    base_severity: int
    window_seconds: int
    params: dict[str, Any]
    description: str
    mitre_hint: str | None = None

    def __post_init__(self) -> None:
        if not RULE_ID.match(self.rule_id):
            raise DetectionError("rule_id must look like D-001")
        if not 1 <= self.base_severity <= 5:
            raise DetectionError("base_severity is 1 to 5")
        if self.window_seconds <= 0 or self.window_seconds > int(MAX_WINDOW.total_seconds()):
            raise DetectionError("window_seconds must be positive and within MAX_WINDOW")


class Detector(Protocol):
    @property
    def spec(self) -> RuleSpec: ...

    def run(self, window: EventWindow) -> list[DetectionResult]: ...
