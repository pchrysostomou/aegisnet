"""How well did correlation group the alerts? (Milestone 3, Chunk 17; ADR-025.)

`docs/evaluation.md` §4 defines three correlation measures, and this is where they are
computed. Pure, like the grouping it scores: the same alerts and the same ground truth always
produce the same numbers, so the table in §8 is a fact about the code rather than a note
somebody typed.

Grouping is scored **pairwise**, which is the standard way to score a clustering against a
known one and the only way that is fair to both failure modes. For every pair of alerts we ask
two questions: did correlation put them in one case, and should it have? A rule that puts
everything in one case gets perfect recall and terrible precision; a rule that gives every
alert its own case gets the opposite. Counting cases alone would hide both.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from itertools import combinations
from uuid import UUID

from aegisnet.domain.correlation import Proposal


class CorrelationEvalError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class GroupingMetrics:
    """The pairwise counts, and the case-level measures §4 asks for."""

    alerts: int
    incidents_expected: int
    incidents_produced: int
    pair_tp: int
    pair_fp: int
    pair_fn: int
    contaminated_incidents: int

    @property
    def precision(self) -> float:
        """Of the alert pairs correlation put together, how many belonged together.

        One when it never put together a pair that did not belong — including when it put no
        pair together at all, because a grouping that makes no claim makes no wrong claim.
        """
        predicted = self.pair_tp + self.pair_fp
        return 1.0 if predicted == 0 else self.pair_tp / predicted

    @property
    def recall(self) -> float:
        """Of the alert pairs that belonged together, how many correlation found."""
        actual = self.pair_tp + self.pair_fn
        return 1.0 if actual == 0 else self.pair_tp / actual

    @property
    def pairs_scored(self) -> int:
        """How many pairs the ratios above rest on. Printed with them, because 1.00 over six
        pairs and 1.00 over none are the same two characters and very different claims."""
        return self.pair_tp + self.pair_fp + self.pair_fn

    @property
    def f1(self) -> float:
        precision, recall = self.precision, self.recall
        return 0.0 if precision + recall == 0 else 2 * precision * recall / (precision + recall)

    @property
    def fragmentation(self) -> float:
        """Incidents produced ÷ incidents expected. Above one is over-splitting one story into
        several; below one is collapsing separate stories into one."""
        if self.incidents_expected == 0:
            raise CorrelationEvalError("a scenario expects at least one incident")
        return self.incidents_produced / self.incidents_expected

    @property
    def contamination(self) -> float:
        """The share of produced incidents holding alerts from more than one scenario."""
        if self.incidents_produced == 0:
            return 0.0
        return self.contaminated_incidents / self.incidents_produced


def score(
    proposals: Sequence[Proposal],
    truth: Mapping[UUID, str],
    *,
    incidents_expected: int,
) -> GroupingMetrics:
    """Score a grouping against the scenario each alert really belongs to.

    ``truth`` maps an alert id to a scenario id. Every alert in every proposal must appear in
    it: an alert nobody labelled cannot be scored, and silently ignoring it would flatter the
    result.
    """
    if incidents_expected < 1:
        raise CorrelationEvalError("a scenario expects at least one incident")

    predicted: dict[UUID, int] = {}
    for index, proposal in enumerate(proposals):
        for alert in proposal.alerts:
            if alert.id in predicted:
                raise CorrelationEvalError(f"alert {alert.id} appears in two proposals")
            predicted[alert.id] = index
    missing = sorted(str(alert_id) for alert_id in predicted if alert_id not in truth)
    if missing:
        raise CorrelationEvalError(f"unlabelled alerts: {', '.join(missing)}")

    # Alerts the truth knows about that correlation produced nothing for still count against
    # recall: a pair that should have been grouped and was not is a miss whether the second
    # alert landed in the wrong case or was never raised.
    everyone = sorted(set(predicted) | set(truth), key=lambda value: value.int)
    tp = fp = fn = 0
    for left, right in combinations(everyone, 2):
        together = left in predicted and right in predicted and predicted[left] == predicted[right]
        belongs = truth.get(left) is not None and truth.get(left) == truth.get(right)
        if together and belongs:
            tp += 1
        elif together:
            fp += 1
        elif belongs:
            fn += 1

    contaminated = sum(
        1 for proposal in proposals if len({truth[alert.id] for alert in proposal.alerts}) > 1
    )
    return GroupingMetrics(
        alerts=len(everyone),
        incidents_expected=incidents_expected,
        incidents_produced=len(proposals),
        pair_tp=tp,
        pair_fp=fp,
        pair_fn=fn,
        contaminated_incidents=contaminated,
    )


def markdown_table(metrics: GroupingMetrics) -> str:
    """The §8 correlation block's table, in the shape the document already declares."""
    return "\n".join(
        (
            "| Metric | Value | Target |",
            "|---|---|---|",
            f"| Grouping precision / recall | {metrics.precision:.2f} / {metrics.recall:.2f}"
            f" over {metrics.pairs_scored} alert pairs "
            f"(tp {metrics.pair_tp}, fp {metrics.pair_fp}, fn {metrics.pair_fn})"
            " | 1.00 / 1.00 |",
            f"| Case fragmentation | {metrics.fragmentation:.2f} "
            f"({metrics.incidents_produced} produced ÷ {metrics.incidents_expected} expected)"
            " | 1.0 ± 0.2 |",
            f"| Case contamination | {metrics.contamination:.2f} "
            f"({metrics.contaminated_incidents} of {metrics.incidents_produced} incidents)"
            " | 0 |",
        )
    )


__all__ = ["CorrelationEvalError", "GroupingMetrics", "markdown_table", "score"]
