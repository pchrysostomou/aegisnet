"""D-003 DNS anomaly / possible tunnelling (PRD FR-4.3; specification in
``docs/detection-rules.md``): many high-entropy names under one domain, an NXDOMAIN storm,
or a stream of over-long labels, per querying client."""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import asdict, dataclass, field
from typing import Final

from aegisnet.domain.detectors.model import (
    MAX_SAMPLES,
    DetectionError,
    DetectionResult,
    Entity,
    EventSample,
    EventWindow,
    RuleSpec,
    window_bucket,
)
from aegisnet.domain.enums import EntityType, EventType, SampleRole
from aegisnet.domain.ports import EventRow

SIGNAL_SATURATION: Final = 3.0
SUSPICIOUS_LABEL_CHARS: Final = 16
"""A label shorter than this is never called high-entropy, whatever its characters."""
DOMAIN_CHARS: Final = 128
DEFAULT_ALLOWED_SUFFIXES: Final = (
    "cloudfront.net",
    "akamaiedge.net",
    "akamai.net",
    "edgekey.net",
    "amazonaws.com",
    "azureedge.net",
    "azure.com",
    "windows.net",
    "windowsupdate.com",
    "microsoft.com",
    "googleusercontent.com",
    "googleapis.com",
    "gstatic.com",
    "apple.com",
    "icloud.com",
    "cloudflare.net",
    "fastly.net",
    "in-addr.arpa",
    "ip6.arpa",
)


@dataclass(frozen=True, slots=True)
class DnsAnomalyParams:
    unique_subdomains: int = 50
    """distinct names under one base domain, at least half of them high-entropy (tunnel)"""
    entropy_threshold: float = 3.5
    """bits per character of the longest subdomain label before it counts as random"""
    long_label_chars: int = 40
    long_queries: int = 20
    """distinct names carrying a label of ``long_label_chars`` or more"""
    nxdomain_failures: int = 50
    nxdomain_ratio: float = 0.5
    allowed_suffixes: tuple[str, ...] = DEFAULT_ALLOWED_SUFFIXES
    """CDN and cloud suffixes whose random-looking hostnames are the way they are"""

    def __post_init__(self) -> None:
        for name in ("unique_subdomains", "long_label_chars", "long_queries", "nxdomain_failures"):
            if not 2 <= getattr(self, name) <= 100_000:
                raise DetectionError(f"{name} must be between 2 and 100000")
        if not 0.0 < self.entropy_threshold <= 8.0:
            raise DetectionError("entropy_threshold is bits per character, 0 to 8")
        if not 0.0 < self.nxdomain_ratio <= 1.0:
            raise DetectionError("nxdomain_ratio must be between 0 and 1")
        suffixes = tuple(s.strip().lower().strip(".") for s in self.allowed_suffixes)
        if len(suffixes) > 256 or any(not s or len(s) > 253 for s in suffixes):
            raise DetectionError("allowed_suffixes: at most 256 entries of 1 to 253 characters")
        object.__setattr__(self, "allowed_suffixes", suffixes)


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def base_domain(name: str) -> str:
    labels = name.rstrip(".").lower().split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else labels[0]


def subdomain_labels(name: str) -> list[str]:
    labels = name.rstrip(".").lower().split(".")
    return labels[:-2] if len(labels) > 2 else []


def is_allowed(name: str, suffixes: tuple[str, ...]) -> bool:
    lowered = name.rstrip(".").lower()
    return any(lowered == s or lowered.endswith("." + s) for s in suffixes)


def looks_random(name: str, entropy_threshold: float) -> bool:
    """The longest subdomain label is long enough and high-entropy enough."""
    labels = subdomain_labels(name)
    if not labels:
        return False
    longest = max(labels, key=len)
    return len(longest) >= SUSPICIOUS_LABEL_CHARS and shannon_entropy(longest) >= entropy_threshold


@dataclass
class _Tally:
    events: list[EventRow] = field(default_factory=list)
    names: set[str] = field(default_factory=set)
    query_records: int = 0
    answers: int = 0
    nxdomain: int = 0
    per_domain: dict[str, set[str]] = field(default_factory=dict)


class DnsAnomalyDetector:
    rule_id: Final = "D-003"
    name: Final = "DNS anomaly / possible tunnelling"
    version: Final = 1
    base_severity: Final = 3
    window_seconds: Final = 600
    description: Final = (
        "Per querying client: many distinct high-entropy names under one base domain "
        "(tunnelling shape), an NXDOMAIN storm by count and ratio, or a stream of over-long "
        "labels. CDN and cloud suffixes are allow-listed; volume alone never fires."
    )
    mitre_hint: Final = "T1071.004 Application Layer Protocol: DNS"

    def __init__(self, params: DnsAnomalyParams | None = None) -> None:
        self.params = params or DnsAnomalyParams()

    @property
    def spec(self) -> RuleSpec:
        return RuleSpec(
            rule_id=self.rule_id,
            name=self.name,
            version=self.version,
            base_severity=self.base_severity,
            window_seconds=self.window_seconds,
            params=asdict(self.params),
            description=self.description,
            mitre_hint=self.mitre_hint,
        )

    def _client_of(self, event: EventRow) -> str | None:
        """Queries travel client → resolver, answers (the records carrying an rcode) travel
        resolver → client; both are attributed to the client."""
        if event.dns_rcode is not None:
            return None if event.dest_ip is None else str(event.dest_ip)
        return None if event.src_ip is None else str(event.src_ip)

    def run(self, window: EventWindow) -> list[DetectionResult]:
        per_client: dict[str, _Tally] = {}
        for event in window.events:
            if event.event_type is not EventType.dns:
                continue
            client = self._client_of(event)
            if client is None:
                continue
            tally = per_client.setdefault(client, _Tally())
            tally.events.append(event)
            if event.dns_rcode is not None:
                tally.answers += 1
                if event.dns_rcode.upper() == "NXDOMAIN":
                    tally.nxdomain += 1
                continue
            tally.query_records += 1
            if event.dns_query:
                name = event.dns_query.rstrip(".").lower()
                tally.names.add(name)
                tally.per_domain.setdefault(base_domain(name), set()).add(name)

        bucket = window_bucket(window.start, self.window_seconds)
        results: list[DetectionResult] = []
        for client in sorted(per_client):
            tally = per_client[client]
            result = self._evaluate(client, tally, window, bucket)
            if result is not None:
                results.append(result)
        return results

    def _evaluate(
        self, client: str, tally: _Tally, window: EventWindow, bucket: object
    ) -> DetectionResult | None:
        params = self.params
        signals: dict[str, float] = {}

        top_domain, top_names, top_suspicious = "", 0, 0
        for domain, names in tally.per_domain.items():
            if is_allowed(domain, params.allowed_suffixes):
                continue
            suspicious = sum(1 for n in names if looks_random(n, params.entropy_threshold))
            if len(names) > top_names:
                top_domain, top_names, top_suspicious = domain, len(names), suspicious
            if len(names) >= params.unique_subdomains and suspicious * 2 >= len(names):
                signals["tunnel"] = max(
                    signals.get("tunnel", 0.0), len(names) / params.unique_subdomains
                )

        if tally.answers and tally.nxdomain >= params.nxdomain_failures:
            ratio = tally.nxdomain / tally.answers
            if ratio >= params.nxdomain_ratio:
                signals["nxdomain"] = tally.nxdomain / params.nxdomain_failures

        long_names = sum(
            1
            for n in tally.names
            if not is_allowed(n, params.allowed_suffixes)
            and any(len(label) >= params.long_label_chars for label in subdomain_labels(n))
        )
        if long_names >= params.long_queries:
            signals["long_labels"] = long_names / params.long_queries

        if not signals or not tally.events:
            return None
        strongest = max(signals.values())
        events = tally.events
        return DetectionResult(
            rule_id=self.rule_id,
            rule_version=self.version,
            entity=Entity(EntityType.src_ip, client),
            window_bucket=bucket,  # type: ignore[arg-type]
            first_seen=events[0].event_time,
            last_seen=events[-1].event_time,
            signal_strength=round(min(1.0, strongest / SIGNAL_SATURATION), 4),
            confidence=round(min(1.0, 0.6 + 0.2 * (len(signals) - 1)), 4),
            event_count=len(events),
            evidence={
                "signals": sorted(signals),
                "distinct_names": len(tally.names),
                "query_records": tally.query_records,
                "answers": tally.answers,
                "nxdomain_answers": tally.nxdomain,
                "nxdomain_ratio": round(tally.nxdomain / tally.answers, 4)
                if tally.answers
                else 0.0,
                "top_domain": top_domain[:DOMAIN_CHARS],
                "top_domain_names": top_names,
                "top_domain_suspicious": top_suspicious,
                "long_names": long_names,
                "threshold_unique_subdomains": params.unique_subdomains,
                "threshold_nxdomain": params.nxdomain_failures,
                "threshold_long_queries": params.long_queries,
                "window_start": window.start,
                "window_end": window.end,
            },
            samples=_samples(events),
        )


def _samples(events: list[EventRow]) -> tuple[EventSample, ...]:
    chosen = [EventSample(events[0].id, SampleRole.first)]
    if len(events) > 1:
        chosen.append(EventSample(events[-1].id, SampleRole.last))
    taken = {s.event_id for s in chosen}
    middle = [e for e in events if e.id not in taken]
    room = min(MAX_SAMPLES, 20) - len(chosen)
    if room > 0 and middle:
        step = max(1, len(middle) // room)
        chosen.extend(EventSample(e.id, SampleRole.sample) for e in middle[::step][:room])
    return tuple(chosen)
