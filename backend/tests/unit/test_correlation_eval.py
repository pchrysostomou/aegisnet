"""Scoring a grouping against known truth (ADR-025).

The metrics exist to catch correlation getting worse, so these tests are mostly about what
each number does when it *should* look bad: a rule that lumps everything together, a rule that
splits everything apart, and the boundary cases where a naive implementation divides by zero
or quietly reports a perfect score for having done nothing.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from aegisnet.domain.correlation import AlertFacts, Proposal, group
from aegisnet.domain.correlation_eval import CorrelationEvalError, markdown_table, score
from aegisnet.domain.enums import EntityType

pytestmark = pytest.mark.unit

T0 = datetime(2026, 9, 5, 9, 0, tzinfo=UTC)


def alert(number: int, *, entity: str, rule: str = "D-001", minutes: int = 0) -> AlertFacts:
    return AlertFacts(
        id=UUID(int=number),
        rule_id=rule,
        severity=3,
        entity_type=EntityType.src_ip,
        entity_value=entity,
        first_seen=T0 + timedelta(minutes=minutes),
        last_seen=T0 + timedelta(minutes=minutes, seconds=30),
    )


def proposal(*alerts: AlertFacts) -> Proposal:
    first = alerts[0]
    return Proposal(
        key=first.key,
        entity_type=first.entity_type,
        entity_value=first.entity_value,
        alerts=alerts,
    )


HOST_A, HOST_B = "10.10.0.42", "10.10.0.77"
A1 = alert(1, entity=HOST_A, rule="D-001")
A2 = alert(2, entity=HOST_A, rule="D-002", minutes=2)
A3 = alert(3, entity=HOST_A, rule="D-004", minutes=4)
B1 = alert(4, entity=HOST_B, rule="D-001", minutes=1)
TRUTH = {A1.id: "compromise", A2.id: "compromise", A3.id: "compromise", B1.id: "unrelated"}


def test_a_perfect_grouping_scores_one_on_everything() -> None:
    metrics = score(
        [proposal(A1, A2, A3), proposal(B1)],
        TRUTH,
        incidents_expected=2,
    )
    assert (metrics.precision, metrics.recall, metrics.f1) == (1.0, 1.0, 1.0)
    assert metrics.fragmentation == 1.0
    assert metrics.contamination == 0.0
    assert metrics.alerts == 4
    assert (metrics.pair_tp, metrics.pair_fp, metrics.pair_fn) == (3, 0, 0)


def test_sweeping_an_unrelated_alert_into_the_case_costs_precision_and_shows_as_contamination() -> (
    None
):
    metrics = score([proposal(A1, A2, A3, B1)], TRUTH, incidents_expected=2)
    # Three pairs really belong together; the three pairs involving the bystander do not.
    assert (metrics.pair_tp, metrics.pair_fp, metrics.pair_fn) == (3, 3, 0)
    assert metrics.precision == 0.5
    assert metrics.recall == 1.0
    assert metrics.fragmentation == 0.5, "one case where two were expected"
    assert metrics.contamination == 1.0, "the only case mixes two scenarios"


def test_splitting_one_story_into_three_costs_recall_not_precision() -> None:
    metrics = score(
        [proposal(A1), proposal(A2), proposal(A3), proposal(B1)],
        TRUTH,
        incidents_expected=2,
    )
    assert (metrics.pair_tp, metrics.pair_fp, metrics.pair_fn) == (0, 0, 3)
    assert metrics.precision == 1.0, "it never claimed a pair that was wrong"
    assert metrics.recall == 0.0
    assert metrics.f1 == 0.0
    assert metrics.fragmentation == 2.0
    assert metrics.contamination == 0.0


def test_an_alert_correlation_produced_nothing_for_still_counts_against_recall() -> None:
    """A missing alert is a missed pairing, not an absent one. Scoring only what was produced
    would let a correlation engine improve its numbers by dropping evidence."""
    metrics = score([proposal(A1, A2)], TRUTH, incidents_expected=2)
    assert metrics.pair_tp == 1
    assert metrics.pair_fn == 2, "A3 pairs with A1 and A2 and was never grouped"
    assert metrics.recall == 1 / 3
    assert metrics.alerts == 4


def test_a_grouping_that_claims_nothing_claims_nothing_wrong() -> None:
    metrics = score([], {B1.id: "unrelated"}, incidents_expected=1)
    assert metrics.precision == 1.0
    assert metrics.recall == 1.0, "a single alert has no pair to miss"
    assert metrics.incidents_produced == 0
    assert metrics.contamination == 0.0, "no incident can be contaminated"
    assert metrics.fragmentation == 0.0


def test_an_alert_nobody_labelled_is_an_error_rather_than_a_free_pass() -> None:
    with pytest.raises(CorrelationEvalError, match="unlabelled"):
        score([proposal(A1, A2)], {A1.id: "compromise"}, incidents_expected=1)


def test_an_alert_in_two_proposals_is_refused() -> None:
    with pytest.raises(CorrelationEvalError, match="two proposals"):
        score([proposal(A1), proposal(A1)], TRUTH, incidents_expected=1)


@pytest.mark.parametrize("expected", [0, -1])
def test_a_scenario_expecting_no_incident_is_refused(expected: int) -> None:
    with pytest.raises(CorrelationEvalError):
        score([proposal(A1)], TRUTH, incidents_expected=expected)


def test_the_real_grouping_function_scores_perfectly_on_this_shape() -> None:
    """Not a tautology: `group` is given the four alerts and has to separate them by entity
    on its own, which is the policy the metric exists to watch."""
    metrics = score(group([A1, A2, A3, B1]), TRUTH, incidents_expected=2)
    assert metrics.precision == metrics.recall == 1.0
    assert metrics.fragmentation == 1.0 and metrics.contamination == 0.0


def test_the_table_reports_every_metric_with_its_target() -> None:
    table = markdown_table(score([proposal(A1, A2, A3), proposal(B1)], TRUTH, incidents_expected=2))
    assert "Grouping precision / recall | 1.00 / 1.00 over 3 alert pairs" in table
    assert "(tp 3, fp 0, fn 0)" in table
    assert "Case fragmentation | 1.00 (2 produced ÷ 2 expected)" in table
    assert "Case contamination | 0.00 (0 of 2 incidents)" in table
