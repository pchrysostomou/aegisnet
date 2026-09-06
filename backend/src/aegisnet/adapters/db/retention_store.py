"""The only code in this project that deletes a row (Milestone 6, Chunk 25; ADR-033).

It connects as `aegisnet_retention`, which can `SELECT` and `DELETE` on four tables and do
nothing else anywhere — so the worst a bug here can do is remove rows the policy already said
were removable, and it cannot touch a case, an alert or a brief even by mistake.

Three properties are worth stating, because each one is a decision rather than an accident.

**Every statement is a literal.** A table name never reaches SQL from a variable and neither
does a column name; the statements below are written out, one per table, and chosen from a
dictionary by the policy's own constant. A `DELETE` assembled from strings is the last place a
project should discover it has a formatting bug.

**Deletes are batched.** A first run against a table nobody has pruned could be millions of
rows, and one statement would hold locks for as long as it took. Each pass removes at most
`batch` rows chosen by primary key, and a run stops after `max_batches` passes with the rest
left for tomorrow — the policy is a promise about age, not about finishing tonight.

**An event an alert points at is never old enough.** `alert_events.event_id` is
`ON DELETE CASCADE`, so deleting such an event does not fail: it quietly removes the alert's
evidence and leaves the alert behind with nothing to show. The `events` statement excludes
them, and that exclusion is the reason this store cannot be one generic query.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Final

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from aegisnet.domain.retention import AUDIT_LOG, DETECTOR_RUNS, EVENTS, INGEST_REJECTS

# One statement per table, written out. The `ctid`/primary-key sub-select is what bounds a
# pass; `NOT EXISTS` on `alert_events` is what protects evidence.
_DELETE: Final[dict[str, str]] = {
    EVENTS: """
        DELETE FROM events
         WHERE id IN (
               SELECT e.id
                 FROM events AS e
                WHERE e.event_time < :before
                  AND NOT EXISTS (SELECT 1 FROM alert_events AS ae WHERE ae.event_id = e.id)
                LIMIT :batch
         )
    """,
    INGEST_REJECTS: """
        DELETE FROM ingest_rejects
         WHERE id IN (SELECT id FROM ingest_rejects WHERE created_at < :before LIMIT :batch)
    """,
    DETECTOR_RUNS: """
        DELETE FROM detector_runs
         WHERE id IN (SELECT id FROM detector_runs WHERE created_at < :before LIMIT :batch)
    """,
    AUDIT_LOG: """
        DELETE FROM audit_log
         WHERE id IN (SELECT id FROM audit_log WHERE occurred_at < :before LIMIT :batch)
    """,
}

_COUNT: Final[dict[str, str]] = {
    EVENTS: """
        SELECT count(*) FROM events AS e
         WHERE e.event_time < :before
           AND NOT EXISTS (SELECT 1 FROM alert_events AS ae WHERE ae.event_id = e.id)
    """,
    INGEST_REJECTS: "SELECT count(*) FROM ingest_rejects WHERE created_at < :before",
    DETECTOR_RUNS: "SELECT count(*) FROM detector_runs WHERE created_at < :before",
    AUDIT_LOG: "SELECT count(*) FROM audit_log WHERE occurred_at < :before",
}


@dataclass(frozen=True, slots=True)
class TableOutcome:
    table: str
    removed: int
    remaining: int
    """How many rows the policy still says are old. Non-zero after a run means the batch
    ceiling was reached, not that something went wrong."""


class UnknownRetentionTableError(KeyError):
    """A rule with no statement. Only reachable by adding a rule and forgetting the SQL, which
    is exactly the mistake worth failing loudly on."""


class SqlRetentionStore:
    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    async def count(self, table: str, before: datetime) -> int:
        statement = _COUNT.get(table)
        if statement is None:
            raise UnknownRetentionTableError(table)
        async with self._engine.connect() as connection:
            result = await connection.execute(text(statement), {"before": before})
            return int(result.scalar_one())

    async def prune(
        self, table: str, before: datetime, *, batch: int, max_batches: int
    ) -> TableOutcome:
        """Remove rows older than `before`, `batch` at a time, and say what is left.

        Each pass is its own transaction. A run that is interrupted has therefore deleted whole
        batches and nothing partial, and the next run resumes from wherever it stopped — which
        is the behaviour a policy about age wants, since the rows do not get younger.
        """
        statement = _DELETE.get(table)
        if statement is None:
            raise UnknownRetentionTableError(table)

        removed = 0
        for _pass in range(max_batches):
            async with self._engine.begin() as connection:
                result = await connection.execute(
                    text(statement), {"before": before, "batch": batch}
                )
                deleted = result.rowcount or 0
            removed += deleted
            if deleted < batch:
                break
        return TableOutcome(table=table, removed=removed, remaining=await self.count(table, before))


__all__ = ["SqlRetentionStore", "TableOutcome", "UnknownRetentionTableError"]
