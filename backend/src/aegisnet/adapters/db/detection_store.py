"""SQL implementations of the detection ports (Milestone 2, revision 0003).

All run as the runtime role. The alert insert relies on the UNIQUE ``dedup_key``: a
re-sweep over the same window hands the store keys it already holds and
``ON CONFLICT DO NOTHING`` keeps the original rows and their links untouched.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from decimal import Decimal
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from aegisnet.adapters.db.models import (
    Alert,
    AlertAsset,
    AlertEvent,
    AssetBaseline,
    DetectionRule,
    DetectorRun,
)
from aegisnet.domain.enums import (
    AlertAssetRole,
    AlertStatus,
    BaselineMetric,
    DetectorRunStatus,
    EntityType,
    SampleRole,
)
from aegisnet.domain.pagination import decode_time_id, encode_time_id
from aegisnet.domain.ports import (
    AlertDetail,
    AlertFilter,
    AlertRecord,
    BaselineRecord,
    DetectorRunRecord,
    NewAlert,
    Page,
    RuleRecord,
)


def _rule(row: DetectionRule) -> RuleRecord:
    return RuleRecord(
        id=row.id,
        rule_id=row.rule_id,
        name=row.name,
        version=row.version,
        enabled=row.enabled,
        base_severity=row.base_severity,
        window_seconds=row.window_seconds,
        params=dict(row.params),
        description=row.description,
        mitre_hint=row.mitre_hint,
        updated_at=row.updated_at,
    )


def _run(row: DetectorRun, rule_id: str) -> DetectorRunRecord:
    return DetectorRunRecord(
        id=row.id,
        rule_id=rule_id,
        window_start=row.window_start,
        window_end=row.window_end,
        events_examined=row.events_examined,
        alerts_created=row.alerts_created,
        status=DetectorRunStatus(row.status),
        error_detail=row.error_detail,
        duration_ms=row.duration_ms,
        created_at=row.created_at,
    )


def _alert(row: Alert, rule_id: str) -> AlertRecord:
    return AlertRecord(
        id=row.id,
        rule_id=rule_id,
        rule_version=row.rule_version,
        dedup_key=row.dedup_key,
        severity=row.severity,
        confidence=float(row.confidence),
        severity_rationale=dict(row.severity_rationale),
        entity_type=EntityType(row.entity_type),
        entity_value=row.entity_value,
        first_seen=row.first_seen,
        last_seen=row.last_seen,
        evidence=dict(row.evidence),
        event_count=row.event_count,
        status=AlertStatus(row.status),
        created_at=row.created_at,
    )


class SqlRuleStore:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._sessions = session_factory

    async def upsert(
        self,
        *,
        rule_id: str,
        name: str,
        version: int,
        base_severity: int,
        window_seconds: int,
        params: dict[str, Any],
        description: str,
        mitre_hint: str | None,
        now: datetime,
    ) -> RuleRecord:
        async with self._sessions() as session, session.begin():
            row = (
                await session.execute(select(DetectionRule).where(DetectionRule.rule_id == rule_id))
            ).scalar_one_or_none()
            if row is None:
                row = DetectionRule(
                    rule_id=rule_id,
                    name=name,
                    version=version,
                    base_severity=base_severity,
                    window_seconds=window_seconds,
                    params=params,
                    description=description,
                    mitre_hint=mitre_hint,
                    updated_at=now,
                )
                session.add(row)
            else:
                changed = (
                    row.name != name
                    or row.version != version
                    or row.base_severity != base_severity
                    or row.window_seconds != window_seconds
                    or dict(row.params) != params
                    or row.description != description
                    or row.mitre_hint != mitre_hint
                )
                if changed:
                    row.name = name
                    row.version = version
                    row.base_severity = base_severity
                    row.window_seconds = window_seconds
                    row.params = params
                    row.description = description
                    row.mitre_hint = mitre_hint
                    row.updated_at = now
            await session.flush()
            return _rule(row)

    async def list(self) -> tuple[RuleRecord, ...]:
        async with self._sessions() as session:
            rows = (
                await session.execute(select(DetectionRule).order_by(DetectionRule.rule_id))
            ).scalars()
            return tuple(_rule(row) for row in rows)

    async def set_enabled(self, rule_id: str, enabled: bool, now: datetime) -> RuleRecord | None:
        async with self._sessions() as session, session.begin():
            row = (
                await session.execute(select(DetectionRule).where(DetectionRule.rule_id == rule_id))
            ).scalar_one_or_none()
            if row is None:
                return None
            row.enabled = enabled
            row.updated_at = now
            await session.flush()
            return _rule(row)


async def _rule_ids(session: AsyncSession) -> dict[str, UUID]:
    rows = (await session.execute(select(DetectionRule.rule_id, DetectionRule.id))).all()
    return {row.rule_id: row.id for row in rows}


class SqlDetectorRunStore:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._sessions = session_factory

    async def record(
        self,
        *,
        rule_id: str,
        window_start: datetime,
        window_end: datetime,
        events_examined: int,
        alerts_created: int,
        status: DetectorRunStatus,
        error_detail: str | None,
        duration_ms: int,
        now: datetime,
    ) -> DetectorRunRecord:
        async with self._sessions() as session, session.begin():
            rule_uuid = (await _rule_ids(session))[rule_id]
            row = DetectorRun(
                rule_id=rule_uuid,
                window_start=window_start,
                window_end=window_end,
                events_examined=events_examined,
                alerts_created=alerts_created,
                status=status,
                error_detail=error_detail,
                duration_ms=duration_ms,
                created_at=now,
            )
            session.add(row)
            await session.flush()
            return _run(row, rule_id)

    async def list(self, *, limit: int) -> tuple[DetectorRunRecord, ...]:
        statement = (
            select(DetectorRun, DetectionRule.rule_id)
            .join(DetectionRule, DetectionRule.id == DetectorRun.rule_id)
            .order_by(DetectorRun.created_at.desc(), DetectorRun.id.desc())
            .limit(limit)
        )
        async with self._sessions() as session:
            rows = (await session.execute(statement)).all()
        return tuple(_run(row, rule_id) for row, rule_id in rows)


class SqlAlertStore:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._sessions = session_factory

    async def create_many(self, alerts: Sequence[NewAlert], now: datetime) -> int:
        if not alerts:
            return 0
        created = 0
        async with self._sessions() as session, session.begin():
            rules = await _rule_ids(session)
            for alert in alerts:
                statement = (
                    pg_insert(Alert)
                    .values(
                        rule_id=rules[alert.rule_id],
                        rule_version=alert.rule_version,
                        dedup_key=alert.dedup_key,
                        severity=alert.severity,
                        confidence=Decimal(str(round(alert.confidence, 2))),
                        severity_rationale=alert.severity_rationale,
                        entity_type=alert.entity_type,
                        entity_value=alert.entity_value,
                        first_seen=alert.first_seen,
                        last_seen=alert.last_seen,
                        evidence=alert.evidence,
                        event_count=alert.event_count,
                        status=AlertStatus.open,
                        created_at=now,
                    )
                    .on_conflict_do_nothing(index_elements=["dedup_key"])
                    .returning(Alert.id)
                )
                alert_id = (await session.execute(statement)).scalar_one_or_none()
                if alert_id is None:
                    continue
                created += 1
                if alert.samples:
                    await session.execute(
                        pg_insert(AlertEvent)
                        .values(
                            [
                                {"alert_id": alert_id, "event_id": event_id, "role": role}
                                for event_id, role in alert.samples
                            ]
                        )
                        .on_conflict_do_nothing()
                    )
                if alert.assets:
                    await session.execute(
                        pg_insert(AlertAsset)
                        .values(
                            [
                                {"alert_id": alert_id, "asset_id": asset_id, "role": role}
                                for asset_id, role in alert.assets
                            ]
                        )
                        .on_conflict_do_nothing()
                    )
        return created

    async def list(self, query: AlertFilter) -> Page[AlertRecord]:
        statement = select(Alert, DetectionRule.rule_id).join(
            DetectionRule, DetectionRule.id == Alert.rule_id
        )
        if query.severity_min is not None:
            statement = statement.where(Alert.severity >= query.severity_min)
        if query.rule_id is not None:
            statement = statement.where(DetectionRule.rule_id == query.rule_id)
        if query.entity_type is not None:
            statement = statement.where(Alert.entity_type == query.entity_type)
        if query.entity_value is not None:
            statement = statement.where(Alert.entity_value == query.entity_value)
        if query.status is not None:
            statement = statement.where(Alert.status == query.status)
        if query.time_from is not None:
            statement = statement.where(Alert.first_seen >= query.time_from)
        if query.time_to is not None:
            statement = statement.where(Alert.first_seen < query.time_to)
        if query.cursor is not None:
            moment, last_id = decode_time_id(query.cursor)
            statement = statement.where(
                (Alert.first_seen < moment) | ((Alert.first_seen == moment) & (Alert.id < last_id))
            )
        statement = statement.order_by(Alert.first_seen.desc(), Alert.id.desc()).limit(
            query.limit + 1
        )
        async with self._sessions() as session:
            rows = (await session.execute(statement)).all()
        has_more = len(rows) > query.limit
        rows = rows[: query.limit]
        items = tuple(_alert(row, rule_id) for row, rule_id in rows)
        next_cursor = (
            encode_time_id(items[-1].first_seen, items[-1].id) if has_more and items else None
        )
        return Page(items=items, next_cursor=next_cursor)

    async def get(self, alert_id: UUID) -> AlertDetail | None:
        async with self._sessions() as session:
            found = (
                await session.execute(
                    select(Alert, DetectionRule.rule_id)
                    .join(DetectionRule, DetectionRule.id == Alert.rule_id)
                    .where(Alert.id == alert_id)
                )
            ).one_or_none()
            if found is None:
                return None
            row, rule_id = found
            events = (
                await session.execute(
                    select(AlertEvent.event_id, AlertEvent.role)
                    .where(AlertEvent.alert_id == alert_id)
                    .order_by(AlertEvent.event_id)
                )
            ).all()
            assets = (
                await session.execute(
                    select(AlertAsset.asset_id, AlertAsset.role)
                    .where(AlertAsset.alert_id == alert_id)
                    .order_by(AlertAsset.asset_id)
                )
            ).all()
        return AlertDetail(
            alert=_alert(row, rule_id),
            events=tuple((event_id, SampleRole(role)) for event_id, role in events),
            assets=tuple((asset_id, AlertAssetRole(role)) for asset_id, role in assets),
        )


def _baseline(row: AssetBaseline) -> BaselineRecord:
    return BaselineRecord(
        id=row.id,
        asset_id=row.asset_id,
        metric=BaselineMetric(row.metric),
        window_days=row.window_days,
        mean=float(row.mean),
        stddev=float(row.stddev),
        p95=float(row.p95),
        sample_count=row.sample_count,
        computed_at=row.computed_at,
    )


class SqlBaselineStore:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._sessions = session_factory

    async def upsert(
        self,
        *,
        asset_id: UUID,
        metric: BaselineMetric,
        window_days: int,
        mean: float,
        stddev: float,
        p95: float,
        sample_count: int,
        now: datetime,
    ) -> BaselineRecord:
        values = {
            "asset_id": asset_id,
            "metric": metric,
            "window_days": window_days,
            "mean": mean,
            "stddev": stddev,
            "p95": p95,
            "sample_count": sample_count,
            "computed_at": now,
        }
        statement = (
            pg_insert(AssetBaseline)
            .values(**values)
            .on_conflict_do_update(
                index_elements=["asset_id", "metric", "window_days"],
                set_={
                    k: values[k] for k in ("mean", "stddev", "p95", "sample_count", "computed_at")
                },
            )
            .returning(AssetBaseline)
        )
        async with self._sessions() as session, session.begin():
            row = (await session.execute(statement)).scalar_one()
            return _baseline(row)

    async def list(self, *, metric: BaselineMetric | None = None) -> tuple[BaselineRecord, ...]:
        statement = select(AssetBaseline).order_by(
            AssetBaseline.asset_id, AssetBaseline.metric, AssetBaseline.window_days
        )
        if metric is not None:
            statement = statement.where(AssetBaseline.metric == metric)
        async with self._sessions() as session:
            rows = (await session.execute(statement)).scalars()
            return tuple(_baseline(row) for row in rows)
