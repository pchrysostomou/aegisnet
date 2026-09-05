"""Severity = f(rule base severity, asset criticality, signal strength), clamped 1..5, with
the formula recorded next to the result so any alert can reproduce its own score
(FR-5.2, delivery plan M2 acceptance)."""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Final

from aegisnet.domain.detectors.model import DetectionError

FORMULA: Final = (
    "clamp(floor(base + 0.5 * (asset_criticality - 3) + 2 * (signal_strength - 0.5) + 0.5), 1, 5)"
)
DEFAULT_CRITICALITY: Final = 3
"""Used when the entity is not an inventoried asset; the rationale says so."""


@dataclass(frozen=True, slots=True)
class SeverityScore:
    value: int
    rationale: dict[str, Any]


def _check(base_severity: int, signal_strength: float, criticality: int) -> None:
    if not 1 <= base_severity <= 5:
        raise DetectionError("base_severity is 1 to 5")
    if not 1 <= criticality <= 5:
        raise DetectionError("asset_criticality is 1 to 5")
    if not (math.isfinite(signal_strength) and 0 <= signal_strength <= 1):
        raise DetectionError("signal_strength must be between 0 and 1")


def score(
    base_severity: int, signal_strength: float, asset_criticality: int | None = None
) -> SeverityScore:
    criticality = DEFAULT_CRITICALITY if asset_criticality is None else asset_criticality
    _check(base_severity, signal_strength, criticality)
    raw = base_severity + 0.5 * (criticality - 3) + 2 * (signal_strength - 0.5)
    value = max(1, min(5, math.floor(raw + 0.5)))
    return SeverityScore(
        value=value,
        rationale={
            "formula": FORMULA,
            "base": base_severity,
            "asset_criticality": criticality,
            "asset_criticality_source": "asset" if asset_criticality is not None else "default",
            "signal_strength": round(signal_strength, 4),
            "raw": round(raw, 4),
            "result": value,
        },
    )


def reproduce(rationale: dict[str, Any]) -> int:
    """Recompute a stored rationale; an alert whose ``result`` differs has been tampered
    with or was produced by a different formula version."""
    if rationale.get("formula") != FORMULA:
        raise DetectionError("unknown severity formula")
    return score(
        int(rationale["base"]),
        float(rationale["signal_strength"]),
        int(rationale["asset_criticality"]),
    ).value
