"""Deterministic, windowed detectors (FR-4, FR-5; delivery plan M2; ADR-017).

A detector is a pure function ``(EventWindow) -> list[DetectionResult]``: no I/O, no clock,
no randomness, so every rule is unit-testable against labelled fixtures. Windows are loaded
and bounded outside this package; results are derived, bounded summaries that a service
turns into alert rows with a severity it can explain (``severity``).
"""

from aegisnet.domain.detectors.addresses import INTERNAL_NETWORKS, is_internal
from aegisnet.domain.detectors.auth_burst import AuthBurstDetector, AuthBurstParams
from aegisnet.domain.detectors.baselines import Summary, summarize
from aegisnet.domain.detectors.beaconing import BeaconingDetector, BeaconingParams
from aegisnet.domain.detectors.dns_anomaly import DnsAnomalyDetector, DnsAnomalyParams
from aegisnet.domain.detectors.model import (
    MAX_EVIDENCE_CHARS,
    MAX_EVIDENCE_ITEMS,
    MAX_EVIDENCE_KEYS,
    MAX_SAMPLES,
    MAX_WINDOW,
    MAX_WINDOW_EVENTS,
    Baseline,
    DetectionError,
    DetectionResult,
    Detector,
    Entity,
    EventSample,
    EventWindow,
    RuleSpec,
    bounded_evidence,
    window_bucket,
)
from aegisnet.domain.detectors.port_scan import PortScanDetector, PortScanParams
from aegisnet.domain.detectors.registry import UnknownRuleError, default_detectors, get_detector
from aegisnet.domain.detectors.severity import (
    DEFAULT_CRITICALITY,
    FORMULA,
    SeverityScore,
    reproduce,
    score,
)
from aegisnet.domain.detectors.volume_anomaly import VolumeAnomalyDetector, VolumeAnomalyParams
from aegisnet.domain.enums import EntityType, SampleRole

__all__ = [
    "DEFAULT_CRITICALITY",
    "FORMULA",
    "INTERNAL_NETWORKS",
    "MAX_EVIDENCE_CHARS",
    "MAX_EVIDENCE_ITEMS",
    "MAX_EVIDENCE_KEYS",
    "MAX_SAMPLES",
    "MAX_WINDOW",
    "MAX_WINDOW_EVENTS",
    "AuthBurstDetector",
    "AuthBurstParams",
    "Baseline",
    "BeaconingDetector",
    "BeaconingParams",
    "DetectionError",
    "DetectionResult",
    "Detector",
    "DnsAnomalyDetector",
    "DnsAnomalyParams",
    "Entity",
    "EntityType",
    "EventSample",
    "EventWindow",
    "PortScanDetector",
    "PortScanParams",
    "RuleSpec",
    "SampleRole",
    "SeverityScore",
    "Summary",
    "UnknownRuleError",
    "VolumeAnomalyDetector",
    "VolumeAnomalyParams",
    "bounded_evidence",
    "default_detectors",
    "get_detector",
    "is_internal",
    "reproduce",
    "score",
    "summarize",
    "window_bucket",
]
