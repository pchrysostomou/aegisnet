"""The detection sweep (Milestone 2, Chunk 9; ADR-018).

``sweep(start, end)`` loads the interval's events once, bounded, then runs every
registered rule over its own grid of ``window_seconds`` buckets sliced from that load.
Each rule's outcome is one ``detector_runs`` row; a rule that raises is recorded as
``error`` and never stops the others. Alerts get their severity here, where the asset
inventory is reachable, with the rationale that reproduces it, and are handed to the store
under their ``dedup_key``, so sweeping the same interval twice creates nothing new.
"""

from __future__ import annotations

import bisect
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from typing import Any
from uuid import UUID

from aegisnet.domain.detectors import (
    MAX_WINDOW,
    MAX_WINDOW_EVENTS,
    DetectionError,
    DetectionResult,
    Detector,
    EventWindow,
    default_detectors,
    score,
    window_bucket,
)
from aegisnet.domain.enums import AlertAssetRole, DetectorRunStatus, EntityType
from aegisnet.domain.eve.sanitize import clean_text
from aegisnet.domain.pagination import check_limit, decode_time_id
from aegisnet.domain.ports import (
    AlertDetail,
    AlertFilter,
    AlertRecord,
    AlertStore,
    DetectorRunRecord,
    DetectorRunStore,
    EventRow,
    EventWindowStore,
    NewAlert,
    Page,
    RuleRecord,
    RuleStore,
)
from aegisnet.logging import get_logger
from aegisnet.services.asset_service import AssetService

logger = get_logger(__name__)

MAX_RUNS_LISTED = 200


class SweepError(ValueError):
    """The requested interval is not one the sweep will run."""


class AlertNotFoundError(LookupError):
    pass


def utc_now() -> datetime:
    return datetime.now(tz=UTC)


@dataclass(frozen=True, slots=True)
class SweepOutcome:
    window_start: datetime
    window_end: datetime
    events_examined: int
    truncated: bool
    runs: tuple[DetectorRunRecord, ...]

    @property
    def alerts_created(self) -> int:
        return sum(run.alerts_created for run in self.runs)


def _aware(moment: datetime, name: str) -> datetime:
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise SweepError(f"{name} must carry a UTC offset")
    return moment


def validate_interval(start: datetime, end: datetime) -> None:
    """An interval the sweep will run: aware, ordered, at most ``MAX_WINDOW`` long."""
    _aware(start, "window start")
    _aware(end, "window end")
    if end <= start:
        raise SweepError("window end must be after its start")
    if end - start > MAX_WINDOW:
        raise SweepError(f"a sweep covers at most {MAX_WINDOW}; split longer intervals")


def _buckets(
    start: datetime, end: datetime, window_seconds: int
) -> list[tuple[datetime, datetime]]:
    """The rule's grid over ``[start, end)``: aligned bucket starts, so the dedup keys a
    sweep produces do not depend on where the operator's interval happened to begin."""
    step = timedelta(seconds=window_seconds)
    first = window_bucket(start, window_seconds)
    out: list[tuple[datetime, datetime]] = []
    cursor = first
    while cursor < end:
        out.append((cursor, cursor + step))
        cursor += step
    return out


def _slice(
    events: Sequence[EventRow], times: Sequence[datetime], start: datetime, end: datetime
) -> tuple[EventRow, ...]:
    lo = bisect.bisect_left(times, start)
    hi = bisect.bisect_left(times, end)
    return tuple(events[lo:hi])


class DetectionService:
    def __init__(
        self,
        rules: RuleStore,
        runs: DetectorRunStore,
        alerts: AlertStore,
        events: EventWindowStore,
        assets: AssetService,
        *,
        detectors: Sequence[Detector] | None = None,
        clock: Callable[[], datetime] = utc_now,
        max_events: int = MAX_WINDOW_EVENTS,
    ) -> None:
        self._rules = rules
        self._runs = runs
        self._alerts = alerts
        self._events = events
        self._assets = assets
        self._detectors = tuple(detectors) if detectors is not None else default_detectors()
        self._clock = clock
        self._max_events = max_events

    # ---------------------------------------------------------------- rules
    async def sync_rules(self) -> dict[str, RuleRecord]:
        """Bring ``detection_rules`` up to the code: the registry is what an alert is
        reproducible against, so it is written before any rule runs."""
        now = self._clock()
        synced: dict[str, RuleRecord] = {}
        for detector in self._detectors:
            spec = detector.spec
            synced[spec.rule_id] = await self._rules.upsert(
                rule_id=spec.rule_id,
                name=spec.name,
                version=spec.version,
                base_severity=spec.base_severity,
                window_seconds=spec.window_seconds,
                params=spec.params,
                description=spec.description,
                mitre_hint=spec.mitre_hint,
                now=now,
            )
        return synced

    async def list_rules(self) -> tuple[RuleRecord, ...]:
        return await self._rules.list()

    # ---------------------------------------------------------------- sweep
    def validate_interval(self, start: datetime, end: datetime) -> None:
        validate_interval(start, end)

    async def sweep(self, start: datetime, end: datetime) -> SweepOutcome:
        validate_interval(start, end)
        rules = await self.sync_rules()
        events, truncated = await self._events.load(start, end, max_events=self._max_events)
        times = [event.event_time for event in events]
        runs: list[DetectorRunRecord] = []
        for detector in self._detectors:
            spec = detector.spec
            rule = rules[spec.rule_id]
            started = time.perf_counter()
            status = DetectorRunStatus.success
            detail: str | None = None
            created = 0
            if not rule.enabled:
                status, detail = DetectorRunStatus.skipped, "rule disabled"
            elif truncated:
                status, detail = (
                    DetectorRunStatus.skipped,
                    f"window holds more than {self._max_events} events; narrow the interval",
                )
            else:
                try:
                    created = await self._run_rule(detector, events, times, start, end)
                except Exception as error:  # noqa: BLE001 - isolation is the point (ARCHITECTURE §7)
                    status = DetectorRunStatus.error
                    detail = clean_text(f"{type(error).__name__}: {error}", 256)
                    logger.error(
                        "detector_failed",
                        extra={"rule_id": spec.rule_id, "error_type": type(error).__name__},
                    )
            runs.append(
                await self._runs.record(
                    rule_id=spec.rule_id,
                    window_start=start,
                    window_end=end,
                    events_examined=len(events),
                    alerts_created=created,
                    status=status,
                    error_detail=detail,
                    duration_ms=int((time.perf_counter() - started) * 1000),
                    now=self._clock(),
                )
            )
        logger.info(
            "detection_sweep_done",
            extra={
                "events_examined": len(events),
                "truncated": truncated,
                "alerts_created": sum(run.alerts_created for run in runs),
                "rules": len(runs),
            },
        )
        return SweepOutcome(start, end, len(events), truncated, tuple(runs))

    async def _run_rule(
        self,
        detector: Detector,
        events: Sequence[EventRow],
        times: Sequence[datetime],
        start: datetime,
        end: datetime,
    ) -> int:
        spec = detector.spec
        created = 0
        now = self._clock()
        for bucket_start, bucket_end in _buckets(start, end, spec.window_seconds):
            window = EventWindow(
                bucket_start, bucket_end, _slice(events, times, bucket_start, bucket_end)
            )
            if not window.events:
                continue
            results = detector.run(window)
            new_alerts = [await self._to_alert(result, spec.base_severity) for result in results]
            created += await self._alerts.create_many(new_alerts, now)
        return created

    async def _to_alert(self, result: DetectionResult, base_severity: int) -> NewAlert:
        criticality: int | None = None
        linked: list[tuple[UUID, AlertAssetRole]] = []
        if result.entity.type in (EntityType.src_ip, EntityType.dest_ip):
            try:
                address = ip_address(result.entity.value)
            except ValueError as error:
                raise DetectionError("an address entity must be an IP address") from error
            resolved = await self._assets.resolve(address)
            if resolved is not None:
                criticality = resolved.asset.criticality
                role = (
                    AlertAssetRole.source
                    if result.entity.type is EntityType.src_ip
                    else AlertAssetRole.destination
                )
                linked.append((resolved.asset.id, role))
        severity = score(base_severity, result.signal_strength, criticality)
        return NewAlert(
            rule_id=result.rule_id,
            rule_version=result.rule_version,
            dedup_key=result.dedup_key,
            severity=severity.value,
            confidence=result.confidence,
            severity_rationale=severity.rationale,
            entity_type=result.entity.type,
            entity_value=result.entity.value,
            first_seen=result.first_seen,
            last_seen=result.last_seen,
            evidence=result.evidence,
            event_count=result.event_count,
            samples=tuple((sample.event_id, sample.role) for sample in result.samples),
            assets=tuple(linked),
        )

    # ---------------------------------------------------------------- reads
    async def list_alerts(self, query: AlertFilter) -> Page[AlertRecord]:
        check_limit(query.limit)
        if query.cursor is not None:
            decode_time_id(query.cursor)
        if (
            query.time_from is not None
            and query.time_to is not None
            and query.time_to <= query.time_from
        ):
            raise SweepError("to must be after from")
        return await self._alerts.list(query)

    async def get_alert(self, alert_id: UUID) -> AlertDetail:
        detail = await self._alerts.get(alert_id)
        if detail is None:
            raise AlertNotFoundError("unknown alert")
        return detail

    async def list_runs(self, *, limit: int) -> tuple[DetectorRunRecord, ...]:
        if not 1 <= limit <= MAX_RUNS_LISTED:
            raise SweepError(f"limit must be between 1 and {MAX_RUNS_LISTED}")
        return await self._runs.list(limit=limit)


def describe(outcome: SweepOutcome) -> dict[str, Any]:
    """The JSON the CLI and the logs print for a sweep."""
    return {
        "window_start": outcome.window_start,
        "window_end": outcome.window_end,
        "events_examined": outcome.events_examined,
        "truncated": outcome.truncated,
        "alerts_created": outcome.alerts_created,
        "runs": [
            {
                "rule_id": run.rule_id,
                "status": run.status,
                "alerts_created": run.alerts_created,
                "duration_ms": run.duration_ms,
                "error_detail": run.error_detail,
            }
            for run in outcome.runs
        ],
    }
