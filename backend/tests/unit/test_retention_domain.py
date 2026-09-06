"""The retention policy as data (ADR-033).

Deletion is the one thing this project does that cannot be undone, so what is deletable is
written down as a value and checked here without a database anywhere near it.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from aegisnet.adapters.db.models import ALL_TABLES
from aegisnet.domain.retention import (
    AUDIT_LOG,
    DETECTOR_RUNS,
    EVENTS,
    INGEST_REJECTS,
    RETAINED_FOREVER,
    describe,
    plan,
    rules,
)

pytestmark = pytest.mark.unit

NOW = datetime(2026, 9, 6, 12, 0, tzinfo=UTC)
DEFAULTS = {"events_days": 90, "rejects_days": 30, "detector_runs_days": 30, "audit_days": 365}


def test_every_table_is_either_pruned_or_kept_forever_and_never_both() -> None:
    """The two lists together are the decision. A table missing from both is a table nobody
    decided about, which is the state this test exists to make impossible."""
    pruned = {rule.table for rule in rules(**DEFAULTS)}
    kept = set(RETAINED_FOREVER)

    assert not (pruned & kept), "a table cannot both age and be kept"
    assert pruned | kept == set(ALL_TABLES), "undecided: " + str(set(ALL_TABLES) ^ (pruned | kept))


def test_the_things_a_case_is_made_of_are_never_pruned() -> None:
    """A case is what this project produces. The raw traffic ages; the conclusion does not."""
    pruned = {rule.table for rule in rules(**DEFAULTS)}
    for table in (
        "incidents",
        "incident_timeline",
        "incident_notes",
        "alerts",
        "alert_events",
        "investigation_briefs",
        "brief_citations",
    ):
        assert table not in pruned, table


def test_only_the_events_rule_protects_evidence() -> None:
    """`alert_events.event_id` is ON DELETE CASCADE, so deleting a sampled event does not fail
    — it removes the alert's evidence quietly. That is why this one rule is different."""
    protecting = [rule.table for rule in rules(**DEFAULTS) if rule.protects_evidence]
    assert protecting == [EVENTS]


def test_a_cutoff_is_the_period_subtracted_from_one_reading_of_the_clock() -> None:
    cutoffs = {c.table: c.before for c in plan(NOW, rules(**DEFAULTS))}
    assert cutoffs[EVENTS] == NOW - timedelta(days=90)
    assert cutoffs[INGEST_REJECTS] == NOW - timedelta(days=30)
    assert cutoffs[DETECTOR_RUNS] == NOW - timedelta(days=30)
    assert cutoffs[AUDIT_LOG] == NOW - timedelta(days=365)


def test_one_run_uses_one_clock() -> None:
    """A run that takes an hour must not widen its own window by an hour before it reaches the
    last table, so every cutoff comes from the same instant."""
    cutoffs = plan(NOW, rules(**DEFAULTS))
    assert {c.before + timedelta(days=c.rule.days) for c in cutoffs} == {NOW}


def test_the_audit_trail_is_kept_longest() -> None:
    """Bulk goes first and the record of what happened goes last. A retention policy that
    forgets who did what before it forgets the traffic has its priorities backwards."""
    by_table = {rule.table: rule.days for rule in rules(**DEFAULTS)}
    assert by_table[AUDIT_LOG] == max(by_table.values())


def test_the_policy_reads_as_a_sentence_before_it_is_agreed_to() -> None:
    lines = [describe(cutoff) for cutoff in plan(NOW, rules(**DEFAULTS))]
    assert any(
        "events" in line and "except events an alert still points at" in line for line in lines
    )
    assert any("audit_log" in line and "365 days" in line for line in lines)
    # The audit cutoff is a year back, so the dates are not all in the current year — which
    # is the whole point of printing them rather than the period alone.
    assert any("2025-09-06" in line for line in lines), "365 days before 2026-09-06"
    assert all("older than" in line and "before" in line for line in lines)


def test_the_period_is_whatever_the_deployment_set() -> None:
    short = rules(events_days=1, rejects_days=2, detector_runs_days=3, audit_days=30)
    assert [rule.days for rule in short] == [1, 2, 3, 30]
