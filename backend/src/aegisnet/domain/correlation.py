"""Which alerts belong to the same story (Milestone 3; ADR-023).

Correlation here is deliberately small and deterministic: alerts about **the same entity**
that happened **close enough together in time** are one case. That is all. It is not a
graph, it is not a model, and it does not try to notice that a scan of one host and an upload
from another are the same actor — because a rule that guesses is a rule an analyst has to
double-check, and this project would rather show a fragmented case than a confident wrong one.

The grouping is a pure function of the alerts it is given. Nothing here reads a clock, a
database or a configuration file, so a correlation run can be replayed from stored alerts and
produce the same answer — which is what makes `docs/delivery-plan.md`'s "correlation is
idempotent" a property rather than a hope.

What this module produces are *proposals*: groups of alerts with the key and window that
bound them. Deciding whether a proposal joins an existing case, opens a new one, or is
cross-referenced against a closed one belongs to the service, because those decisions need
state this module deliberately does not have.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Final
from uuid import UUID

from aegisnet.domain.enums import EntityType
from aegisnet.domain.incidents import IncidentError, Severity, severity_of, title_for

# How far apart two alerts about one entity may be and still be the same story. An hour is
# long enough to hold a scan, the auth attempts that follow it and the transfer after those,
# and short enough that yesterday's noise does not join today's case. It is measured from the
# end of what the group has so far, so a case grows while the activity continues and closes
# when it stops.
DEFAULT_JOIN_GAP: Final = timedelta(hours=1)
# A case cannot grow forever on the back of a slow drip: past this span the next alert starts
# a new one, so an incident stays something a human can read in one sitting.
MAX_INCIDENT_SPAN: Final = timedelta(hours=24)
MAX_ALERTS_PER_GROUP: Final = 500


class CorrelationError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class AlertFacts:
    """What correlation needs to know about an alert, and nothing else.

    Deliberately not the stored `AlertRecord`: this module is pure domain, and taking a
    narrow structure keeps it that way while making the tests read as scenarios rather than
    as database rows.
    """

    id: UUID
    rule_id: str
    severity: int
    entity_type: EntityType
    entity_value: str
    first_seen: datetime
    last_seen: datetime

    def __post_init__(self) -> None:
        if self.first_seen.tzinfo is None or self.last_seen.tzinfo is None:
            raise CorrelationError("alert times are timezone-aware")
        if self.last_seen < self.first_seen:
            raise CorrelationError("an alert ends after it starts")
        if not self.entity_value:
            raise CorrelationError("an alert names its entity")

    @property
    def key(self) -> str:
        """The entity, in the same shape the alert dedup keys use: ``src_ip=10.0.0.5``."""
        return f"{self.entity_type.value}={self.entity_value}"


@dataclass(frozen=True, slots=True)
class Proposal:
    """A set of alerts that belong together, with everything a case needs to be opened."""

    key: str
    entity_type: EntityType
    entity_value: str
    alerts: tuple[AlertFacts, ...] = field(default_factory=tuple)

    @property
    def window_start(self) -> datetime:
        return min(alert.first_seen for alert in self.alerts)

    @property
    def window_end(self) -> datetime:
        return max(alert.last_seen for alert in self.alerts)

    @property
    def rule_ids(self) -> tuple[str, ...]:
        return tuple(sorted({alert.rule_id for alert in self.alerts}))

    @property
    def distinct_rule_count(self) -> int:
        return len(self.rule_ids)

    def severity(self) -> Severity:
        return severity_of((a.severity for a in self.alerts), (a.rule_id for a in self.alerts))

    def title(self, asset_hostname: str | None = None) -> str:
        return title_for(self.rule_ids, self.entity_value, asset_hostname)

    def joins(self, alert: AlertFacts, *, gap: timedelta = DEFAULT_JOIN_GAP) -> bool:
        """Would this alert continue the story? Same entity, and beginning no later than
        ``gap`` after the last thing that happened — with the whole case still inside
        ``MAX_INCIDENT_SPAN``."""
        if alert.key != self.key:
            return False
        if alert.first_seen < self.window_start:
            # Ordering is the caller's job; an out-of-order alert is a programming error
            # rather than a data condition, and silently accepting it would make the result
            # depend on input order, which is exactly what idempotence forbids.
            raise CorrelationError("alerts must be presented in ascending first_seen order")
        if alert.first_seen - self.window_end > gap:
            return False
        return max(self.window_end, alert.last_seen) - self.window_start <= MAX_INCIDENT_SPAN


def group(alerts: Iterable[AlertFacts], *, gap: timedelta = DEFAULT_JOIN_GAP) -> list[Proposal]:
    """Every proposal the given alerts support, in a stable order.

    One pass per entity: alerts are sorted by when they began, and each either continues the
    group before it or starts a new one. Two alerts about different entities never meet, which
    is the whole of the "no guessing" policy — and the reason a multi-stage attack against one
    host produces one case while the same stages against three hosts produce three.
    """
    ordered = sorted(alerts, key=lambda a: (a.first_seen, a.last_seen, a.id.int))
    if len(ordered) > MAX_ALERTS_PER_GROUP * 20:
        raise CorrelationError(f"more than {MAX_ALERTS_PER_GROUP * 20} alerts in one run")

    open_groups: dict[str, list[AlertFacts]] = {}
    finished: list[Proposal] = []

    def close(key: str) -> None:
        members = open_groups.pop(key, [])
        if members:
            finished.append(_proposal(members))

    for alert in ordered:
        current = open_groups.get(alert.key)
        if current is None:
            open_groups[alert.key] = [alert]
            continue
        proposal = _proposal(current)
        if proposal.joins(alert, gap=gap) and len(current) < MAX_ALERTS_PER_GROUP:
            current.append(alert)
        else:
            close(alert.key)
            open_groups[alert.key] = [alert]
    for key in list(open_groups):
        close(key)

    # Stable and independent of the order the entities happened to be seen in.
    return sorted(finished, key=lambda p: (p.window_start, p.key))


def _proposal(members: Sequence[AlertFacts]) -> Proposal:
    if not members:  # pragma: no cover - callers never pass an empty group
        raise CorrelationError("a proposal has at least one alert")
    first = members[0]
    return Proposal(
        key=first.key,
        entity_type=first.entity_type,
        entity_value=first.entity_value,
        alerts=tuple(members),
    )


def describe(proposals: Sequence[Proposal]) -> dict[str, object]:
    """A one-line summary for a log or a CLI, with no alert content in it."""
    try:
        escalated = sum(1 for p in proposals if p.severity().escalated)
    except IncidentError:  # pragma: no cover - a proposal always has an alert
        escalated = 0
    return {
        "proposals": len(proposals),
        "alerts": sum(len(p.alerts) for p in proposals),
        "escalated": escalated,
        "entities": len({p.key for p in proposals}),
    }
