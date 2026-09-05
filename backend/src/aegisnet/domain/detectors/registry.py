"""The rules that ship, with their default parameters. The persisted ``detection_rules``
table (M2, later chunk) is seeded from ``spec`` and is what an alert is reproducible
against; this module is the in-process source of truth for the code that runs."""

from __future__ import annotations

from aegisnet.domain.detectors.model import Detector
from aegisnet.domain.detectors.port_scan import PortScanDetector


class UnknownRuleError(LookupError):
    pass


def default_detectors() -> tuple[Detector, ...]:
    return (PortScanDetector(),)


def get_detector(rule_id: str) -> Detector:
    for detector in default_detectors():
        if detector.spec.rule_id == rule_id:
            return detector
    raise UnknownRuleError(f"unknown rule {rule_id!r}")
