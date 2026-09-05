"""The severity formula: recorded, reproducible, clamped (FR-5.2)."""

from __future__ import annotations

import pytest

from aegisnet.domain.detectors import FORMULA, DetectionError, reproduce, score

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    ("base", "signal", "criticality", "expected"),
    [
        (3, 0.5, None, 3),  # the neutral case: base severity unchanged
        (3, 1.0, None, 4),  # strong signal lifts one step
        (3, 0.0, None, 2),  # threshold-grazing signal drops one step
        (3, 1.0, 5, 5),  # critical asset plus strong signal saturates
        (3, 0.75, 4, 4),  # 3 + 0.5 + 0.5 = 4
        (1, 0.0, 1, 1),  # clamps at 1
        (5, 1.0, 5, 5),  # clamps at 5
        (2, 0.25, 2, 1),  # 2 - 0.5 - 0.5 = 1
    ],
)
def test_the_formula_and_its_clamps(
    base: int, signal: float, criticality: int | None, expected: int
) -> None:
    result = score(base, signal, criticality)
    assert result.value == expected
    assert result.rationale["formula"] == FORMULA and result.rationale["result"] == expected
    assert result.rationale["asset_criticality_source"] == (
        "asset" if criticality is not None else "default"
    )
    assert reproduce(result.rationale) == expected


def test_a_tampered_or_foreign_rationale_is_caught() -> None:
    rationale = dict(score(3, 0.5).rationale)
    rationale["result"] = 5
    assert reproduce(rationale) == 3  # the stored result is not trusted, only recomputed
    with pytest.raises(DetectionError, match="formula"):
        reproduce({**rationale, "formula": "something else"})


@pytest.mark.parametrize(
    ("base", "signal", "criticality"),
    [(0, 0.5, 3), (6, 0.5, 3), (3, 1.1, 3), (3, -0.1, 3), (3, 0.5, 0), (3, float("nan"), 3)],
)
def test_out_of_range_inputs_are_refused(base: int, signal: float, criticality: int) -> None:
    with pytest.raises(DetectionError):
        score(base, signal, criticality)
