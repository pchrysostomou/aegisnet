"""The statistics behind ``asset_baselines`` (data model; D-005). Pure, so the job that
writes them and the tests that check them agree by construction."""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Summary:
    mean: float
    stddev: float
    p95: float
    sample_count: int


def summarize(values: Sequence[float]) -> Summary:
    """Mean, population standard deviation and the nearest-rank 95th percentile."""
    if not values:
        return Summary(0.0, 0.0, 0.0, 0)
    ordered = sorted(float(v) for v in values)
    count = len(ordered)
    mean = sum(ordered) / count
    stddev = math.sqrt(sum((v - mean) ** 2 for v in ordered) / count)
    rank = max(1, math.ceil(0.95 * count))
    return Summary(mean=mean, stddev=stddev, p95=ordered[rank - 1], sample_count=count)
