"""What may be deleted, and when (Milestone 6, Chunk 25; ADR-033).

Retention is the only place in this project that destroys anything, so the policy is written
down here as data — pure, with no database in reach — and the SQL that carries it out lives one
layer down where it can be read against this.

Three things shape it.

**Not everything ages.** `incidents`, `alerts` and the brief tables have no period at all: a
case is the thing this project exists to produce, and the evidence a case rests on outlives the
raw traffic it came from. What ages is the bulk — the events, the parse failures, the detector
run log — and the audit trail, which ages because a trail nobody prunes is a trail that grows
without bound.

**Evidence a case rests on is not bulk.** `alert_events` links an alert to a sample of the
events that produced it, and that foreign key is `ON DELETE CASCADE` — so deleting an old event
does not fail, it silently removes an alert's evidence and leaves the alert standing with
nothing behind it. The exported report's provenance appendix would go blank and nothing would
say why. A linked event is therefore kept regardless of age, and the number of them is bounded
by the sample size, so the cost of keeping them is small and known.

**A period is a promise, not a schedule.** The cutoffs here are computed from a clock the caller
passes in, which is what lets a test say "on this day, these rows are old" without waiting.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Final

EVENTS: Final = "events"
INGEST_REJECTS: Final = "ingest_rejects"
DETECTOR_RUNS: Final = "detector_runs"
AUDIT_LOG: Final = "audit_log"

RETAINED_FOREVER: Final = (
    "incidents",
    "incident_alerts",
    "incident_timeline",
    "incident_notes",
    "alerts",
    "alert_events",
    "alert_assets",
    "investigation_briefs",
    "brief_citations",
    "assets",
    "asset_networks",
    "asset_baselines",
    "detection_rules",
    "ingest_batches",
    "users",
    "service_tokens",
    "refresh_tokens",
)
"""Everything with no retention period, listed rather than implied. A table that appears in
neither this tuple nor `RULES` is a table nobody decided about, and the database suite fails on
one — which is the point of writing both lists out."""


@dataclass(frozen=True, slots=True)
class RetentionRule:
    """One table's policy. `column` is the timestamp that decides age; `protects_evidence`
    marks the one table where a row can be too important to delete regardless of it."""

    table: str
    column: str
    days: int
    protects_evidence: bool = False


@dataclass(frozen=True, slots=True)
class RetentionCutoff:
    """A rule with its clock applied. Rows strictly older than `before` are in scope."""

    rule: RetentionRule
    before: datetime

    @property
    def table(self) -> str:
        return self.rule.table


def rules(
    *,
    events_days: int,
    rejects_days: int,
    detector_runs_days: int,
    audit_days: int,
) -> tuple[RetentionRule, ...]:
    """The policy, in the order it is applied.

    Order matters for readability rather than correctness: the bulk tables first and the audit
    trail last, so a run that is interrupted has pruned the cheap things and not the record of
    what it was doing.
    """
    return (
        RetentionRule(EVENTS, "event_time", events_days, protects_evidence=True),
        RetentionRule(INGEST_REJECTS, "created_at", rejects_days),
        RetentionRule(DETECTOR_RUNS, "created_at", detector_runs_days),
        RetentionRule(AUDIT_LOG, "occurred_at", audit_days),
    )


def plan(now: datetime, policy: Sequence[RetentionRule]) -> tuple[RetentionCutoff, ...]:
    """Turn a policy into the cutoffs a single run will use.

    Every cutoff comes from one reading of the clock, so a run that takes an hour does not
    delete an extra hour's worth from the last table it reaches.
    """
    return tuple(
        RetentionCutoff(rule=rule, before=now - timedelta(days=rule.days)) for rule in policy
    )


def describe(cutoff: RetentionCutoff) -> str:
    """One line an operator can read before agreeing to it."""
    kept = " (except events an alert still points at)" if cutoff.rule.protects_evidence else ""
    return (
        f"{cutoff.table}: {cutoff.rule.column} older than {cutoff.rule.days} days"
        f" — before {cutoff.before.isoformat()}{kept}"
    )


__all__ = [
    "AUDIT_LOG",
    "DETECTOR_RUNS",
    "EVENTS",
    "INGEST_REJECTS",
    "RETAINED_FOREVER",
    "RetentionCutoff",
    "RetentionRule",
    "describe",
    "plan",
    "rules",
]
