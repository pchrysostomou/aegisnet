"""Scoring the rules against labelled cases (T1) and a benign corpus (T2); the arithmetic
behind ``make eval`` and docs/evaluation.md §8 (ADR-020).

A positive case is a true positive only when the rule alerts on *exactly* the expected
entity, at least at the expected severity, and on nothing else; anything short of that is
a false negative. A negative case is a false positive the moment the rule alerts at all.
The benign corpus is scored as alerts per 10 000 events, before dedup would collapse them
across sweeps: it is the operator's "how noisy is this rule on quiet traffic" number.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Literal

from aegisnet.domain.detectors.model import DetectionResult, Entity
from aegisnet.domain.detectors.severity import score

Kind = Literal["positive", "negative"]
Verdict = Literal["TP", "FN", "FP", "TN"]


@dataclass(frozen=True, slots=True)
class Expectation:
    rule_id: str
    case_id: str
    kind: Kind
    entity: Entity | None
    min_severity: int | None


@dataclass(frozen=True, slots=True)
class CaseOutcome:
    expectation: Expectation
    fired: int
    matched: bool
    reason: str

    @property
    def verdict(self) -> Verdict:
        if self.expectation.kind == "positive":
            return "TP" if self.matched else "FN"
        return "FP" if self.fired else "TN"


def judge(
    expectation: Expectation, results: Sequence[DetectionResult], *, base_severity: int
) -> CaseOutcome:
    fired = len(results)
    if expectation.kind == "negative":
        reason = "" if fired == 0 else f"alerted {fired} time(s) on a negative case"
        return CaseOutcome(expectation, fired, fired == 0, reason)
    if expectation.entity is None or expectation.min_severity is None:
        raise ValueError("a positive expectation names its entity and minimum severity")
    if fired == 0:
        return CaseOutcome(expectation, 0, False, "no alert")
    on_entity = [r for r in results if r.entity == expectation.entity]
    if len(on_entity) != 1:
        return CaseOutcome(
            expectation, fired, False, f"{len(on_entity)} alert(s) on the expected entity"
        )
    if fired > 1:
        return CaseOutcome(expectation, fired, False, f"{fired - 1} alert(s) on other entities")
    severity = score(base_severity, on_entity[0].signal_strength).value
    if severity < expectation.min_severity:
        return CaseOutcome(
            expectation, fired, False, f"severity {severity} below {expectation.min_severity}"
        )
    return CaseOutcome(expectation, fired, True, "")


@dataclass(frozen=True, slots=True)
class BenignRun:
    rule_id: str
    events: int
    alerts: int
    buckets: int
    note: str = ""

    @property
    def alerts_per_10k(self) -> float:
        return 0.0 if self.events == 0 else self.alerts * 10_000 / self.events


@dataclass(frozen=True, slots=True)
class RuleMetrics:
    rule_id: str
    tp: int
    fp: int
    fn: int
    tn: int
    benign_events: int
    benign_alerts: int
    benign_note: str = ""

    @property
    def cases(self) -> int:
        return self.tp + self.fp + self.fn + self.tn

    @property
    def precision(self) -> float | None:
        return None if self.tp + self.fp == 0 else self.tp / (self.tp + self.fp)

    @property
    def recall(self) -> float | None:
        return None if self.tp + self.fn == 0 else self.tp / (self.tp + self.fn)

    @property
    def f1(self) -> float | None:
        p, r = self.precision, self.recall
        if p is None or r is None or p + r == 0:
            return None
        return 2 * p * r / (p + r)

    @property
    def alerts_per_10k(self) -> float | None:
        if self.benign_events == 0:
            return None
        return self.benign_alerts * 10_000 / self.benign_events


def summarize(
    outcomes: Iterable[CaseOutcome], benign: Iterable[BenignRun]
) -> tuple[RuleMetrics, ...]:
    counts: dict[str, dict[Verdict, int]] = {}
    for outcome in outcomes:
        tally = counts.setdefault(outcome.expectation.rule_id, {})
        tally[outcome.verdict] = tally.get(outcome.verdict, 0) + 1
    quiet = {run.rule_id: run for run in benign}
    out: list[RuleMetrics] = []
    for rule_id in sorted(set(counts) | set(quiet)):
        tally = counts.get(rule_id, {})
        run = quiet.get(rule_id)
        out.append(
            RuleMetrics(
                rule_id,
                tally.get("TP", 0),
                tally.get("FP", 0),
                tally.get("FN", 0),
                tally.get("TN", 0),
                0 if run is None else run.events,
                0 if run is None else run.alerts,
                "" if run is None else run.note,
            )
        )
    return tuple(out)


def _ratio(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.2f}"


def markdown_table(metrics: Sequence[RuleMetrics], *, corpus: str) -> str:
    """The §8 per-detector table: one row per rule, T1 counts and T2 noise."""
    lines = [
        "| Rule | Corpus | Cases | TP | FP | FN | TN | Precision | Recall | F1 "
        "| Alerts/10k benign |",
        "|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for m in metrics:
        noise = "n/a" if m.alerts_per_10k is None else f"{m.alerts_per_10k:.1f}"
        if m.benign_note:
            noise = f"{noise} ({m.benign_note})"
        lines.append(
            f"| {m.rule_id} | {corpus} | {m.cases} | {m.tp} | {m.fp} | {m.fn} | {m.tn} "
            f"| {_ratio(m.precision)} | {_ratio(m.recall)} | {_ratio(m.f1)} | {noise} |"
        )
    return "\n".join(lines)
