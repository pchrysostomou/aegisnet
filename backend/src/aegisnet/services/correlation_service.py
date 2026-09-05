"""Turning alerts into cases, repeatably (Milestone 3, Chunk 15; ADR-023).

The grouping itself is pure and lives in ``domain/correlation.py``. What is here is the part
that needs state: whether a proposal continues a case that is already open, opens a new one,
or has to start a new one because the case it would have joined is closed.

Three properties are the point, and the tests are written against them rather than against
the implementation:

* **Idempotent.** Running the same window twice adds nothing the second time. The database
  constraints do the enforcing — one alert belongs to one case, and a case says the same thing
  about an alert once — so the property survives concurrent runs, not just repeated ones.
* **A closed case never absorbs a new alert.** It opens a new case and says, in the new case's
  timeline, which case came before it. A closed case is a judgement somebody made; new
  evidence deserves a new case rather than a quiet edit to an old one.
* **Alerts already in a case are left alone.** Correlation adds; it never moves an alert
  between cases, because an analyst may have put it where it is.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Final

from aegisnet.domain.correlation import (
    DEFAULT_JOIN_GAP,
    AlertFacts,
    CorrelationError,
    Proposal,
    describe,
    group,
)
from aegisnet.domain.enums import AlertStatus, TimelineEntryType
from aegisnet.domain.ports import (
    AlertFilter,
    AlertRecord,
    AlertStore,
    IncidentRecord,
    IncidentStore,
    NewIncident,
    NewTimelineEntry,
)
from aegisnet.logging import get_logger

logger = get_logger(__name__)

MAX_WINDOW: Final = timedelta(days=7)
MAX_ALERTS: Final = 5_000
PAGE: Final = 200


class CorrelationRunError(ValueError):
    """The interval asked for cannot be correlated."""


@dataclass(frozen=True, slots=True)
class CaseOutcome:
    """What happened to one proposal."""

    case_number: str
    correlation_key: str
    alerts_linked: int
    created: bool
    superseded: str | None = None
    """The case this one was opened beside, when the story continued into a closed case."""


@dataclass(frozen=True, slots=True)
class CorrelationOutcome:
    start: datetime
    end: datetime
    alerts_considered: int
    alerts_correlated: int
    cases_opened: int
    cases_extended: int
    outcomes: tuple[CaseOutcome, ...]


def validate_interval(start: datetime, end: datetime) -> None:
    for name, moment in (("start", start), ("end", end)):
        if moment.tzinfo is None or moment.utcoffset() is None:
            raise CorrelationRunError(f"correlation {name} must be timezone-aware")
    if end <= start:
        raise CorrelationRunError("the interval ends after it starts")
    if end - start > MAX_WINDOW:
        raise CorrelationRunError(f"correlation covers at most {MAX_WINDOW}; split longer runs")


def facts_of(alert: AlertRecord) -> AlertFacts:
    return AlertFacts(
        id=alert.id,
        rule_id=alert.rule_id,
        severity=alert.severity,
        entity_type=alert.entity_type,
        entity_value=alert.entity_value,
        first_seen=alert.first_seen,
        last_seen=alert.last_seen,
    )


class CorrelationService:
    def __init__(
        self,
        incidents: IncidentStore,
        alerts: AlertStore,
        *,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        join_gap: timedelta = DEFAULT_JOIN_GAP,
    ) -> None:
        self._incidents = incidents
        self._alerts = alerts
        self._clock = clock
        self._join_gap = join_gap

    async def correlate(self, start: datetime, end: datetime) -> CorrelationOutcome:
        """Group every uncorrelated alert in ``[start, end)`` and file the groups as cases."""
        validate_interval(start, end)
        began = time.perf_counter()
        alerts = await self._load(start, end)
        proposals = group((facts_of(alert) for alert in alerts), gap=self._join_gap)

        outcomes: list[CaseOutcome] = []
        for proposal in proposals:
            outcome = await self._file(proposal)
            if outcome is not None:
                outcomes.append(outcome)

        result = CorrelationOutcome(
            start=start,
            end=end,
            alerts_considered=len(alerts),
            alerts_correlated=sum(o.alerts_linked for o in outcomes),
            cases_opened=sum(1 for o in outcomes if o.created),
            cases_extended=sum(1 for o in outcomes if not o.created),
            outcomes=tuple(outcomes),
        )
        logger.info(
            "correlation_done",
            extra={
                "window_start": start.isoformat(),
                "window_end": end.isoformat(),
                "duration_ms": int((time.perf_counter() - began) * 1000),
                **describe(proposals),
                "cases_opened": result.cases_opened,
                "cases_extended": result.cases_extended,
            },
        )
        return result

    async def _load(self, start: datetime, end: datetime) -> list[AlertRecord]:
        """Every alert in the interval that no case has claimed yet, oldest first.

        Correlated alerts are skipped rather than regrouped: an alert already in a case stays
        there, which is what keeps a re-run from moving evidence around under an analyst.
        """
        collected: list[AlertRecord] = []
        cursor: str | None = None
        while True:
            page = await self._alerts.list(
                AlertFilter(
                    status=AlertStatus.open,
                    time_from=start,
                    time_to=end,
                    limit=PAGE,
                    cursor=cursor,
                )
            )
            collected.extend(page.items)
            if len(collected) > MAX_ALERTS:
                raise CorrelationRunError(
                    f"more than {MAX_ALERTS} uncorrelated alerts in one interval; narrow it"
                )
            cursor = page.next_cursor
            if cursor is None:
                break
        return sorted(collected, key=lambda a: (a.first_seen, a.id.int))

    async def _file(self, proposal: Proposal) -> CaseOutcome | None:
        """Open a case for this proposal, or grow the open one it continues."""
        alert_ids = [alert.id for alert in proposal.alerts]
        claimed = await self._incidents.already_linked(alert_ids)
        fresh = [alert for alert in proposal.alerts if alert.id not in claimed]
        if not fresh:
            return None

        now = self._clock()
        existing = await self._incidents.newest_open_for_key(proposal.key)
        if existing is not None and self._continues(existing, proposal):
            linked = await self._incidents.extend(
                existing.id,
                [alert.id for alert in fresh],
                [_alert_entry(alert) for alert in fresh],
                severity=proposal.severity().value,
                severity_rationale=proposal.severity().rationale(),
                title=proposal.title(),
                window_end=proposal.window_end,
                distinct_rule_count=proposal.distinct_rule_count,
                now=now,
            )
            return CaseOutcome(
                case_number=existing.case_number,
                correlation_key=proposal.key,
                alerts_linked=linked,
                created=False,
            )

        superseded = await self._closed_predecessor(proposal)
        entries = [_alert_entry(alert) for alert in fresh]
        if superseded is not None:
            entries.insert(0, _supersedes_entry(superseded, proposal.window_start))
        severity = proposal.severity()
        record = await self._incidents.open_case(
            NewIncident(
                correlation_key=proposal.key,
                title=proposal.title(),
                severity=severity.value,
                severity_rationale=severity.rationale(),
                window_start=proposal.window_start,
                window_end=proposal.window_end,
                distinct_rule_count=proposal.distinct_rule_count,
                alert_ids=tuple(alert.id for alert in fresh),
            ),
            entries,
            now=now,
        )
        return CaseOutcome(
            case_number=record.case_number,
            correlation_key=proposal.key,
            alerts_linked=len(fresh),
            created=True,
            superseded=None if superseded is None else superseded.case_number,
        )

    def _continues(self, existing: IncidentRecord, proposal: Proposal) -> bool:
        """Is this proposal the same story as the open case? Same entity, and starting no
        later than the join gap after the case's last activity."""
        if existing.correlation_key != proposal.key:  # pragma: no cover - the query filters
            return False
        return proposal.window_start - existing.window_end <= self._join_gap

    async def _closed_predecessor(self, proposal: Proposal) -> IncidentRecord | None:
        """The closed case this story would have continued into, if there is one.

        Only a recent one counts: a case closed last month is not the predecessor of today's
        activity on the same host, and saying so in the timeline would be noise rather than
        context.
        """
        closed = await self._incidents.newest_closed_for_key(proposal.key)
        if closed is None:
            return None
        return closed if proposal.window_start - closed.window_end <= self._join_gap else None


def _alert_entry(alert: AlertFacts) -> NewTimelineEntry:
    return NewTimelineEntry(
        occurred_at=alert.first_seen,
        entry_type=TimelineEntryType.alert_fired,
        summary=f"{alert.rule_id} fired on {alert.entity_type.value} {alert.entity_value}",
        detail={
            "rule_id": alert.rule_id,
            "severity": alert.severity,
            "first_seen": alert.first_seen.isoformat(),
            "last_seen": alert.last_seen.isoformat(),
        },
        alert_id=alert.id,
    )


def _supersedes_entry(previous: IncidentRecord, occurred_at: datetime) -> NewTimelineEntry:
    return NewTimelineEntry(
        occurred_at=occurred_at,
        entry_type=TimelineEntryType.observation,
        summary=f"Opened beside {previous.case_number}, which was already closed",
        detail={"previous_case": previous.case_number, "previous_status": previous.status.value},
    )


def summarise(outcome: CorrelationOutcome) -> dict[str, object]:
    """One JSON line for the CLI, naming cases but never alert content."""
    return {
        "window_start": outcome.start.isoformat(),
        "window_end": outcome.end.isoformat(),
        "alerts_considered": outcome.alerts_considered,
        "alerts_correlated": outcome.alerts_correlated,
        "cases_opened": outcome.cases_opened,
        "cases_extended": outcome.cases_extended,
        "cases": [
            {
                "case_number": o.case_number,
                "correlation_key": o.correlation_key,
                "alerts_linked": o.alerts_linked,
                "created": o.created,
                **({"superseded": o.superseded} if o.superseded else {}),
            }
            for o in outcome.outcomes
        ],
    }


__all__ = [
    "CaseOutcome",
    "CorrelationError",
    "CorrelationOutcome",
    "CorrelationRunError",
    "CorrelationService",
    "facts_of",
    "summarise",
    "validate_interval",
]
