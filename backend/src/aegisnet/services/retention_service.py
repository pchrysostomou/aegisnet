"""Running the retention policy, and recording that it ran (Milestone 6, Chunk 25; ADR-033).

The service does two things the store deliberately cannot.

**It offers a dry run, and that is the default everywhere it is reachable.** `plan()` counts
what the policy would remove and removes nothing. An operator's first contact with the only
irreversible thing this project does should be a list, not a result.

**It writes the run into the audit log — as the app role.** The retention role can delete and
cannot write a single row; the app role can write and cannot delete. So the record of a prune
is made by a principal that could not have done the pruning, and the audit log ends up holding
the account of its own trimming. That is a smaller guarantee than it sounds like, and it is
still worth having: a run that removed rows and left no trace would need two credentials.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from aegisnet.adapters.db import engine as db_engine
from aegisnet.adapters.db.audit_store import SqlAuditStore
from aegisnet.adapters.db.retention_store import SqlRetentionStore, TableOutcome
from aegisnet.adapters.db.session import make_session_factory
from aegisnet.config import Settings
from aegisnet.domain.enums import AuditResult
from aegisnet.domain.retention import RetentionCutoff, describe, plan, rules
from aegisnet.logging import get_logger
from aegisnet.services.audit_service import AuditService

if TYPE_CHECKING:  # pragma: no cover - typing only
    from sqlalchemy.ext.asyncio import AsyncEngine

logger = get_logger(__name__)


def utc_now() -> datetime:
    return datetime.now(tz=UTC)


@dataclass(frozen=True, slots=True)
class RetentionPlan:
    """What a run would do, before it does it."""

    cutoffs: tuple[RetentionCutoff, ...]
    counts: dict[str, int]

    @property
    def total(self) -> int:
        return sum(self.counts.values())

    def lines(self) -> list[str]:
        return [f"{describe(cutoff)} — {self.counts[cutoff.table]} rows" for cutoff in self.cutoffs]


@dataclass(frozen=True, slots=True)
class RetentionRun:
    outcomes: tuple[TableOutcome, ...]

    @property
    def removed(self) -> int:
        return sum(outcome.removed for outcome in self.outcomes)

    @property
    def complete(self) -> bool:
        """False when a batch ceiling stopped a table short. The next run finishes it."""
        return all(outcome.remaining == 0 for outcome in self.outcomes)


class RetentionService:
    def __init__(
        self,
        store: SqlRetentionStore,
        audit: AuditService,
        *,
        events_days: int,
        rejects_days: int,
        detector_runs_days: int,
        audit_days: int,
        batch_rows: int,
        max_batches: int,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self._store = store
        self._audit = audit
        self._policy = rules(
            events_days=events_days,
            rejects_days=rejects_days,
            detector_runs_days=detector_runs_days,
            audit_days=audit_days,
        )
        self._batch = batch_rows
        self._max_batches = max_batches
        self._clock = clock

    async def plan(self) -> RetentionPlan:
        """What the policy says is old, right now. Deletes nothing."""
        cutoffs = plan(self._clock(), self._policy)
        counts = {c.table: await self._store.count(c.table, c.before) for c in cutoffs}
        return RetentionPlan(cutoffs=cutoffs, counts=counts)

    async def run(self) -> RetentionRun:
        """Apply the policy and record what it removed.

        The cutoffs are computed once, before the first delete, so a run that takes an hour does
        not quietly widen its own window by an hour before it reaches the last table.
        """
        cutoffs = plan(self._clock(), self._policy)
        outcomes: list[TableOutcome] = []
        for cutoff in cutoffs:
            outcome = await self._store.prune(
                cutoff.table, cutoff.before, batch=self._batch, max_batches=self._max_batches
            )
            outcomes.append(outcome)
            logger.info(
                "retention_pruned",
                extra={
                    "table": outcome.table,
                    "removed": outcome.removed,
                    "remaining": outcome.remaining,
                    "before": cutoff.before.isoformat(),
                },
            )

        run = RetentionRun(outcomes=tuple(outcomes))
        await self._record(run, cutoffs)
        return run

    async def _record(self, run: RetentionRun, cutoffs: Sequence[RetentionCutoff]) -> None:
        """One audit row per run, written by the role that cannot delete."""
        await self._audit.record(
            "retention.pruned",
            target_type="database",
            target_id=None,
            result=AuditResult.success if run.complete else AuditResult.error,
            detail={
                "removed": run.removed,
                "complete": run.complete,
                **{f"removed_{o.table}": o.removed for o in run.outcomes},
                **{f"remaining_{o.table}": o.remaining for o in run.outcomes if o.remaining},
                "oldest_kept": min(c.before for c in cutoffs).isoformat() if cutoffs else None,
            },
        )


def build_retention(settings: Settings) -> tuple[RetentionService, AsyncEngine, AsyncEngine]:
    """The service and the two engines it needs, so the CLI and the nightly actor build it the
    same way.

    Two connections on purpose. The retention role can delete and cannot write; the app role can
    write and cannot delete. The prune runs on the first and the audit row on the second, so no
    single credential in this deployment can both remove rows and account for having done it.
    """
    pruning = db_engine.create_engine_for(settings.retention_url)
    writing = db_engine.create_engine(settings)
    service = RetentionService(
        SqlRetentionStore(pruning),
        AuditService(SqlAuditStore(make_session_factory(writing))),
        events_days=settings.retention_events_days,
        rejects_days=settings.retention_rejects_days,
        detector_runs_days=settings.retention_detector_runs_days,
        audit_days=settings.retention_audit_days,
        batch_rows=settings.retention_batch_rows,
        max_batches=settings.retention_max_batches,
    )
    return service, pruning, writing


__all__ = [
    "RetentionPlan",
    "RetentionRun",
    "RetentionService",
    "build_retention",
    "utc_now",
]
