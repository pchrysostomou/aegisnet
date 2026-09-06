"""Running the policy, and recording that it ran (ADR-033).

The store is stubbed here on purpose: what the SQL does is checked against a real PostgreSQL in
`tests/db/test_retention.py`, and what is left to check is the part above it — that a dry run
deletes nothing, that one run reads the clock once, and that a prune always leaves an account
of itself written by the role that could not have done it.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from aegisnet.adapters.db.retention_store import TableOutcome
from aegisnet.domain.enums import AuditResult
from aegisnet.domain.retention import AUDIT_LOG, EVENTS
from aegisnet.services.audit_service import AuditService
from aegisnet.services.retention_service import RetentionService
from tests.fakes import FakeAuditStore

pytestmark = pytest.mark.unit

NOW = datetime(2026, 9, 6, 12, 0, tzinfo=UTC)
PERIODS = {
    "events_days": 90,
    "rejects_days": 30,
    "detector_runs_days": 30,
    "audit_days": 365,
}


class StubStore:
    """Counts what it was asked, and pretends everything old was removed in one pass."""

    def __init__(self, present: dict[str, int] | None = None, *, leftover: int = 0) -> None:
        self.present = present or {}
        self.leftover = leftover
        self.counted: list[tuple[str, datetime]] = []
        self.pruned: list[tuple[str, datetime, int, int]] = []

    async def count(self, table: str, before: datetime) -> int:
        self.counted.append((table, before))
        return self.present.get(table, 0)

    async def prune(
        self, table: str, before: datetime, *, batch: int, max_batches: int
    ) -> TableOutcome:
        self.pruned.append((table, before, batch, max_batches))
        return TableOutcome(
            table=table, removed=self.present.get(table, 0), remaining=self.leftover
        )


def _service(store: StubStore, audit: AuditService, **overrides: object) -> RetentionService:
    values: dict[str, object] = {**PERIODS, "batch_rows": 500, "max_batches": 10}
    values.update(overrides)
    return RetentionService(
        store,  # type: ignore[arg-type]
        audit,
        clock=lambda: NOW,
        **values,  # type: ignore[arg-type]
    )


@pytest.fixture
def audit_store() -> FakeAuditStore:
    return FakeAuditStore()


@pytest.fixture
def audit(audit_store: FakeAuditStore) -> AuditService:
    return AuditService(audit_store)


async def test_a_dry_run_counts_and_deletes_nothing(
    audit: AuditService, audit_store: FakeAuditStore
) -> None:
    """The default everywhere this is reachable. An operator's first contact with the only
    irreversible thing here should be a list."""
    store = StubStore({EVENTS: 12, AUDIT_LOG: 3})
    outcome = await _service(store, audit).plan()

    assert outcome.total == 15
    assert outcome.counts[EVENTS] == 12
    assert store.pruned == [], "nothing was removed"
    assert audit_store.entries == [], "and nothing was recorded, because nothing happened"
    assert any("except events an alert still points at" in line for line in outcome.lines())


async def test_a_run_removes_what_the_policy_says_and_records_it(
    audit: AuditService, audit_store: FakeAuditStore
) -> None:
    store = StubStore({EVENTS: 12, AUDIT_LOG: 3})
    run = await _service(store, audit).run()

    assert run.removed == 15
    assert run.complete
    assert [table for table, *_ in store.pruned] == [
        EVENTS,
        "ingest_rejects",
        "detector_runs",
        AUDIT_LOG,
    ], "bulk first, the record of what happened last"

    (entry,) = audit_store.entries
    assert entry.action == "retention.pruned"
    assert entry.result is AuditResult.success
    assert entry.detail["removed"] == 15
    assert entry.detail[f"removed_{EVENTS}"] == 12
    assert entry.detail["complete"] is True


async def test_one_run_uses_one_clock(audit: AuditService) -> None:
    """A prune that takes an hour must not widen its own window by an hour before it reaches
    the last table."""
    store = StubStore()
    await _service(store, audit).run()

    for table, before, *_ in store.pruned:
        days = {EVENTS: 90, "ingest_rejects": 30, "detector_runs": 30, AUDIT_LOG: 365}[table]
        assert before == NOW - timedelta(days=days)


async def test_a_run_that_hit_its_ceiling_says_so_rather_than_claiming_success(
    audit: AuditService, audit_store: FakeAuditStore
) -> None:
    """A first prune of a long-neglected table is allowed to leave work for tomorrow. It is not
    allowed to look like it finished."""
    store = StubStore({EVENTS: 500}, leftover=1_200)
    run = await _service(store, audit).run()

    assert not run.complete
    (entry,) = audit_store.entries
    assert entry.result is AuditResult.error, "an incomplete run is not a success"
    assert entry.detail["complete"] is False
    assert entry.detail[f"remaining_{EVENTS}"] == 1_200


async def test_the_batch_settings_reach_the_store(audit: AuditService) -> None:
    store = StubStore()
    await _service(store, audit, batch_rows=250, max_batches=4).run()
    assert {(batch, ceiling) for _t, _b, batch, ceiling in store.pruned} == {(250, 4)}


async def test_the_record_names_no_row_it_deleted(
    audit: AuditService, audit_store: FakeAuditStore
) -> None:
    """Counts and cutoffs, never content. An audit row about pruning the audit log must not
    become a copy of what was pruned."""
    store = StubStore({AUDIT_LOG: 9})
    await _service(store, audit).run()

    (entry,) = audit_store.entries
    assert set(entry.detail) <= {
        "removed",
        "complete",
        "oldest_kept",
        *(f"removed_{t}" for t in (EVENTS, "ingest_rejects", "detector_runs", AUDIT_LOG)),
        *(f"remaining_{t}" for t in (EVENTS, "ingest_rejects", "detector_runs", AUDIT_LOG)),
    }
    assert entry.detail["oldest_kept"] == (NOW - timedelta(days=365)).isoformat()
