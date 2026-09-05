"""D-003 DNS anomaly: the three signals, the allow-list, client attribution, entropy."""

from __future__ import annotations

from datetime import datetime, timedelta
from uuid import uuid4

import pytest

from aegisnet.domain.detectors import (
    DetectionError,
    DnsAnomalyDetector,
    DnsAnomalyParams,
    EventWindow,
)
from aegisnet.domain.detectors.dns_anomaly import (
    base_domain,
    is_allowed,
    looks_random,
    shannon_entropy,
    subdomain_labels,
)
from aegisnet.domain.enums import EventType
from aegisnet.domain.ports import EventRow
from tests.detectors.conftest import WINDOW_END, WINDOW_START, flow_row

pytestmark = pytest.mark.unit

CLIENT = "10.10.0.71"
RESOLVER = "10.10.0.53"
HEX = "0123456789abcdef"


def _dns(
    when: datetime, name: str, *, client: str = CLIENT, rcode: str | None = None, rrtype: str = "A"
) -> EventRow:
    """One DNS record: a query (client → resolver, no rcode) or an answer (resolver → client)."""
    src, dst = (RESOLVER, client) if rcode is not None else (client, RESOLVER)
    base = flow_row(when, src, dst, 53, event_type=EventType.dns, event_id=uuid4())
    return EventRow(
        **{
            **{f: getattr(base, f) for f in base.__dataclass_fields__},
            "dns_query": name,
            "dns_rrtype": rrtype,
            "dns_rcode": rcode,
        }
    )


def _pair(
    when: datetime, name: str, *, rcode: str = "NOERROR", client: str = CLIENT
) -> list[EventRow]:
    return [
        _dns(when, name, client=client),
        _dns(when + timedelta(milliseconds=5), name, client=client, rcode=rcode),
    ]


def _label(i: int, length: int = 40) -> str:
    """A deterministic pseudo-random hex label of exactly ``length`` characters."""
    text = ""
    x = i * 2654435761 % (2**32)
    while len(text) < length:
        x = (x * 1103515245 + 12345) % (2**31)
        text += HEX[(x >> 8) % 16]
    return text[:length]


def _window(rows: list[EventRow]) -> EventWindow:
    return EventWindow(WINDOW_START, WINDOW_END, tuple(rows))


def test_helpers_measure_names_the_documented_way() -> None:
    assert (
        base_domain("a.b.example.com.") == "example.com" and base_domain("localhost") == "localhost"
    )
    assert (
        subdomain_labels("x.y.example.com") == ["x", "y"] and subdomain_labels("example.com") == []
    )
    assert is_allowed("d1.cloudfront.net", DnsAnomalyParams().allowed_suffixes)
    assert is_allowed("CLOUDFRONT.NET.", DnsAnomalyParams().allowed_suffixes)
    assert not is_allowed("cloudfront.net.evil.example", DnsAnomalyParams().allowed_suffixes)
    assert shannon_entropy("") == 0.0 and shannon_entropy("aaaa") == 0.0
    assert shannon_entropy("0123456789abcdef") == pytest.approx(4.0)
    assert looks_random(f"{_label(1)}.t.example.com", 3.5)
    assert not looks_random("svc001.example.org", 3.5)  # short and low entropy
    assert not looks_random("example.com", 3.5)


def test_params_are_bounded() -> None:
    for bad in (
        {"unique_subdomains": 1},
        {"entropy_threshold": 9.0},
        {"nxdomain_ratio": 0.0},
        {"allowed_suffixes": ("",)},
    ):
        with pytest.raises(DetectionError):
            DnsAnomalyParams(**bad)  # type: ignore[arg-type]
    assert DnsAnomalyParams(allowed_suffixes=(" Example.NET. ",)).allowed_suffixes == (
        "example.net",
    )


def test_the_tunnel_signal_needs_many_random_names_under_one_domain() -> None:
    detector = DnsAnomalyDetector(DnsAnomalyParams(unique_subdomains=50))
    rows: list[EventRow] = []
    for i in range(50):
        rows += _pair(WINDOW_START + timedelta(seconds=i), f"{_label(i, 32)}.t.exfil-example.com")
    [hit] = detector.run(_window(rows))
    assert (
        hit.evidence["signals"] == ["tunnel"] and hit.evidence["top_domain"] == "exfil-example.com"
    )
    assert hit.evidence["top_domain_names"] == 50
    assert hit.evidence["top_domain_suspicious"] * 2 >= hit.evidence["top_domain_names"]
    assert hit.entity.value == CLIENT and hit.event_count == 100 and hit.confidence == 0.6
    assert hit.signal_strength == pytest.approx(1 / 3, abs=1e-4)
    # 49 names: under the count
    assert detector.run(_window(rows[:98])) == []
    # 50 names but low-entropy labels: a resolver forwarding for a big organisation
    plain: list[EventRow] = []
    for i in range(150):
        plain += _pair(WINDOW_START + timedelta(seconds=i), f"svc{i:03d}.example.org")
    assert detector.run(_window(plain)) == []
    # 50 random names under an allow-listed suffix
    cdn: list[EventRow] = []
    for i in range(50):
        cdn += _pair(WINDOW_START + timedelta(seconds=i), f"{_label(i, 32)}.cloudfront.net")
    assert detector.run(_window(cdn)) == []


def test_the_nxdomain_signal_needs_count_and_ratio() -> None:
    detector = DnsAnomalyDetector(DnsAnomalyParams(nxdomain_failures=50, nxdomain_ratio=0.5))
    rows: list[EventRow] = []
    for i in range(60):
        rows += _pair(
            WINDOW_START + timedelta(seconds=i),
            f"dga{i}.example",
            rcode="NXDOMAIN" if i < 55 else "NOERROR",
        )
    [hit] = detector.run(_window(rows))
    assert hit.evidence["signals"] == ["nxdomain"] and hit.evidence["nxdomain_answers"] == 55
    assert hit.evidence["nxdomain_ratio"] == pytest.approx(55 / 60, abs=1e-3)
    diluted = rows + [
        row
        for i in range(100)
        for row in _pair(WINDOW_START + timedelta(seconds=100 + i), f"ok{i}.example.org")
    ]
    assert detector.run(_window(diluted)) == []  # 55 of 160: ratio under one half
    few: list[EventRow] = []
    for i in range(49):
        few += _pair(WINDOW_START + timedelta(seconds=i), f"dga{i}.example", rcode="NXDOMAIN")
    assert detector.run(_window(few)) == []


def test_the_long_label_signal_and_the_allow_list() -> None:
    detector = DnsAnomalyDetector(DnsAnomalyParams(long_queries=20, long_label_chars=40))
    rows: list[EventRow] = []
    for i in range(20):
        rows += _pair(WINDOW_START + timedelta(seconds=i), f"{_label(i, 48)}.c2.example.net")
    [hit] = detector.run(_window(rows))
    assert hit.evidence["signals"] == ["long_labels"] and hit.evidence["long_names"] == 20
    allowed: list[EventRow] = []
    for i in range(20):
        allowed += _pair(
            WINDOW_START + timedelta(seconds=i), f"{_label(i, 48)}.execute-api.amazonaws.com"
        )
    assert detector.run(_window(allowed)) == []


def test_several_signals_raise_confidence_and_answers_attribute_to_the_client() -> None:
    detector = DnsAnomalyDetector(
        DnsAnomalyParams(unique_subdomains=20, long_queries=20, nxdomain_failures=20)
    )
    rows: list[EventRow] = []
    for i in range(30):
        rows += _pair(
            WINDOW_START + timedelta(seconds=i), f"{_label(i, 44)}.x.example.net", rcode="NXDOMAIN"
        )
    [hit] = detector.run(_window(rows))
    assert (
        hit.evidence["signals"] == ["long_labels", "nxdomain", "tunnel"] and hit.confidence == 1.0
    )
    assert (
        hit.entity.value == CLIENT
    )  # the answers came from the resolver, the client is the entity
    assert hit.evidence["answers"] == 30 and hit.evidence["query_records"] == 30


def test_non_dns_events_and_volume_alone_never_fire() -> None:
    detector = DnsAnomalyDetector()
    rows = [
        flow_row(WINDOW_START + timedelta(seconds=i), CLIENT, "192.0.2.10", 443) for i in range(500)
    ]
    for i in range(400):
        rows += _pair(WINDOW_START + timedelta(seconds=i), "www.example.org")
    assert detector.run(_window(rows)) == []
    assert DnsAnomalyDetector().spec.rule_id == "D-003" and DnsAnomalyDetector().spec.mitre_hint
