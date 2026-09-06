"""The only thing that may be sent about a case (TB-3).

Everything here is an **allow-list**. A field reaches a packet because somebody named it in
this module; a detector that starts emitting a new evidence key sends nothing new until that
key is classified here, and the packet records that it dropped it. The default for anything
unrecognised is to drop it, which is the only default that fails safe.

What actually goes out is overwhelmingly *derived numbers*: how many ports, how regular the
interval, how many standard deviations above the baseline. Those are what a brief reasons
from, they carry no topology, and — the point of T-4.1 — they are not text, so they cannot
carry an instruction to a model.

Where a string is genuinely needed, it is one of three kinds: a rule id from a fixed
vocabulary this project owns, a token from the pseudonymiser, or a short scalar from a small
allow-listed vocabulary. Nothing an attacker chose is ever passed through as itself.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Final

from aegisnet.domain.redaction.pseudonyms import SUBJECT_LABEL, Pseudonymizer
from aegisnet.domain.redaction.scanner import clean_free_text

MAX_PACKET_BYTES: Final = 24_000
MAX_ALERTS: Final = 12
MAX_EVIDENCE_KEYS: Final = 24
MAX_LIST_ITEMS: Final = 8
MAX_TIMELINE: Final = 20

# Evidence keys whose value is a number, a boolean, or a list of numbers. These are the whole
# point of the packet and pass through untouched.
NUMERIC_KEYS: Final[frozenset[str]] = frozenset(
    {
        "failures",
        "max_burst",
        "burst_seconds",
        "threshold",
        "distinct_targets",
        "signature_ids",
        "connections",
        "mean_interval_seconds",
        "jitter",
        "bytes_out",
        "threshold_connections",
        "max_jitter",
        "distinct_names",
        "query_records",
        "answers",
        "nxdomain_answers",
        "nxdomain_ratio",
        "long_names",
        "threshold_unique_subdomains",
        "threshold_nxdomain",
        "threshold_long_queries",
        "distinct_dest_ports",
        "distinct_dest_hosts",
        "flows",
        "unanswered_flows",
        "threshold_ports",
        "threshold_hosts",
        "sample_dest_ports",
        "threshold_bytes",
        "ratio",
        "baseline_mean",
        "baseline_stddev",
        "baseline_p95",
        "baseline_samples",
        "baseline_window_days",
        "distinct_destinations",
        "top_domain_suspicious",
        # A count of distinct names under the busiest domain, not a name. It sat in
        # ADDRESS_KEYS until Chunk 33, where `Pseudonymizer.tokens` turned the integer
        # into `[]` for every real D-003 alert — the one number saying how large the
        # suspected tunnel is, silently emptied, with `dropped_fields` reporting nothing
        # withheld. The canary test had only ever fed it a *list*, a shape the detector
        # does not produce (`dns_anomaly.py:244` sends `len(names)`).
        "top_domain_names",
    }
)

# Keys whose value is an address or a hostname: topology, and in the DNS rules' case attacker
# chosen. Pseudonymised, never sent as themselves (T-3.2).
ADDRESS_KEYS: Final[frozenset[str]] = frozenset(
    {
        "destination",
        "beaconing_destinations",
        "sample_targets",
        "sample_dest_hosts",
        "sample_destinations",
        "top_domain",
    }
)

# Small, closed vocabularies this project or Suricata owns. Still scanned and capped.
VOCABULARY_KEYS: Final[frozenset[str]] = frozenset({"app_proto", "signals"})

# Times bound the story and identify nobody.
TIME_KEYS: Final[frozenset[str]] = frozenset({"window_start", "window_end"})

# Named so the packet can say it dropped them on purpose rather than by omission.
DROP_KEYS: Final[frozenset[str]] = frozenset({"sample_categories"})


@dataclass(frozen=True, slots=True)
class PacketLimits:
    max_bytes: int = MAX_PACKET_BYTES
    max_alerts: int = MAX_ALERTS
    max_evidence_keys: int = MAX_EVIDENCE_KEYS
    max_list_items: int = MAX_LIST_ITEMS


@dataclass(frozen=True, slots=True)
class AlertEvidence:
    """One alert, reduced to what a brief can reason from."""

    rule_id: str
    severity: int
    confidence: float
    event_count: int
    first_seen: str
    last_seen: str
    entity: str
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class CaseEvidencePacket:
    """What leaves. Every field is here because it was named, not because it was present."""

    case_number: str
    severity: int
    status: str
    distinct_rule_count: int
    window_start: str
    window_end: str
    subject: str
    subject_class: str
    alerts: tuple[AlertEvidence, ...]
    timeline: tuple[str, ...]
    truncated: bool
    dropped_fields: tuple[str, ...]
    """Every key this packet refused, with the reason, so a reviewer can see what was withheld
    rather than having to infer it from an absence."""

    def as_dict(self) -> dict[str, Any]:
        return {
            "case_number": self.case_number,
            "severity": self.severity,
            "status": self.status,
            "distinct_rule_count": self.distinct_rule_count,
            "window_start": self.window_start,
            "window_end": self.window_end,
            "subject": self.subject,
            "subject_class": self.subject_class,
            "alerts": [
                {
                    "rule_id": a.rule_id,
                    "severity": a.severity,
                    "confidence": a.confidence,
                    "event_count": a.event_count,
                    "first_seen": a.first_seen,
                    "last_seen": a.last_seen,
                    "entity": a.entity,
                    "evidence": a.evidence,
                }
                for a in self.alerts
            ],
            "timeline": list(self.timeline),
            "packet_truncated": self.truncated,
        }

    def serialise(self) -> str:
        """The exact bytes a request body would carry. Sorted keys, so the same case produces
        the same string and a content hash can key a cache."""
        return json.dumps(self.as_dict(), sort_keys=True, separators=(",", ":"))


def _iso(moment: datetime | str) -> str:
    return moment if isinstance(moment, str) else moment.isoformat()


def _evidence(
    raw: dict[str, Any],
    names: Pseudonymizer,
    limits: PacketLimits,
    dropped: list[str],
    where: str,
) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key in sorted(raw):
        if len(out) >= limits.max_evidence_keys:
            dropped.append(f"{where}.{key}: evidence key cap")
            continue
        value = raw[key]
        if key in DROP_KEYS:
            dropped.append(f"{where}.{key}: not sent by policy")
        elif key in NUMERIC_KEYS:
            kept = _numeric(value, limits)
            if kept is None:
                dropped.append(f"{where}.{key}: not a number")
            else:
                out[key] = kept
        elif key in ADDRESS_KEYS:
            out[key] = (
                names.token(str(value))
                if isinstance(value, str)
                else names.tokens(value)[: limits.max_list_items]
            )
        elif key in TIME_KEYS:
            out[key] = _iso(value) if isinstance(value, datetime | str) else None
        elif key in VOCABULARY_KEYS:
            kept = _vocabulary(value, key, limits)
            if kept is None:
                dropped.append(f"{where}.{key}: failed the free-text scan")
            else:
                out[key] = kept
        else:
            # The important branch: a key nobody has classified is a key nobody has reviewed.
            dropped.append(f"{where}.{key}: not on the allow-list")
    return out


def _numeric(value: object, limits: PacketLimits) -> object | None:
    if isinstance(value, bool | int | float):
        return value
    if isinstance(value, list | tuple):
        numbers = [v for v in value if isinstance(v, bool | int | float)]
        return numbers[: limits.max_list_items] if len(numbers) == len(value) else None
    return None


def _vocabulary(value: object, key: str, limits: PacketLimits) -> object | None:
    if isinstance(value, str):
        return clean_free_text(value, field=key, limit=32)
    if isinstance(value, list | tuple):
        kept = [
            cleaned
            for item in value[: limits.max_list_items]
            if isinstance(item, str) and (cleaned := clean_free_text(item, field=key, limit=32))
        ]
        return kept
    return None


def build_packet(
    *,
    case_number: str,
    severity: int,
    status: str,
    distinct_rule_count: int,
    window_start: datetime,
    window_end: datetime,
    subject: str,
    alerts: list[dict[str, Any]],
    timeline_summaries: list[str] | None = None,
    limits: PacketLimits | None = None,
) -> tuple[CaseEvidencePacket, Pseudonymizer]:
    """Build the packet and the local mapping that resolves its tokens.

    ``alerts`` are plain dictionaries rather than ORM rows or `AlertRecord`s, and that is the
    point: the caller has to name what it is passing, so nothing can be handed in wholesale.
    """
    bounds = limits or PacketLimits()
    names = Pseudonymizer(subject=subject)
    dropped: list[str] = []

    kept: list[AlertEvidence] = []
    for index, alert in enumerate(alerts):
        if len(kept) >= bounds.max_alerts:
            dropped.append(f"alerts[{index}]: alert cap of {bounds.max_alerts}")
            continue
        where = f"alerts[{index}]"
        entity = str(alert.get("entity_value", ""))
        kept.append(
            AlertEvidence(
                rule_id=str(alert.get("rule_id", "")),
                severity=int(alert.get("severity", 0)),
                confidence=float(alert.get("confidence", 0.0)),
                event_count=int(alert.get("event_count", 0)),
                first_seen=_iso(alert["first_seen"]),
                last_seen=_iso(alert["last_seen"]),
                entity=names.token(entity) if entity else SUBJECT_LABEL,
                evidence=_evidence(
                    dict(alert.get("evidence") or {}), names, bounds, dropped, where
                ),
            )
        )

    # Timeline summaries are written by this project (`correlation_service`, `incident_service`)
    # and never by a sensor — but they *quote the entity*, so they are scrubbed of addresses and
    # names before they are scanned. Without that the timeline would carry the very values the
    # rest of the packet withholds, which is what the canary suite caught.
    lines: list[str] = []
    for index, summary in enumerate(timeline_summaries or []):
        if len(lines) >= MAX_TIMELINE:
            break
        cleaned = clean_free_text(names.scrub(summary), field=f"timeline[{index}]", limit=120)
        if cleaned is None:
            dropped.append(f"timeline[{index}]: failed the free-text scan")
        else:
            lines.append(cleaned)

    packet = CaseEvidencePacket(
        case_number=case_number,
        severity=severity,
        status=status,
        distinct_rule_count=distinct_rule_count,
        window_start=_iso(window_start),
        window_end=_iso(window_end),
        subject=SUBJECT_LABEL,
        subject_class=_subject_class(subject),
        alerts=tuple(kept),
        timeline=tuple(lines),
        truncated=len(alerts) > bounds.max_alerts,
        dropped_fields=tuple(dropped),
    )
    return _fit(packet, bounds), names


def _subject_class(subject: str) -> str:
    from aegisnet.domain.redaction.pseudonyms import label_for

    kind = label_for(subject)
    return {"int": "private", "ext": "public", "domain": "domain"}[kind]


def _fit(packet: CaseEvidencePacket, limits: PacketLimits) -> CaseEvidencePacket:
    """Shrink until the serialised packet fits, dropping whole alerts from the end.

    Truncation is explicit and recorded (T-3.5): a packet that quietly got smaller would be a
    packet whose brief silently described less than the analyst thinks it did.
    """
    current = packet
    while len(current.serialise().encode("utf-8")) > limits.max_bytes and current.alerts:
        current = CaseEvidencePacket(
            **{
                **{f: getattr(current, f) for f in current.__slots__},
                "alerts": current.alerts[:-1],
                "truncated": True,
                "dropped_fields": (
                    *current.dropped_fields,
                    f"alerts[{len(current.alerts) - 1}]: byte cap of {limits.max_bytes}",
                ),
            }
        )
    return current
