"""Normalisation of the hand-built fixtures: promotion, mapping, rejects, idempotency."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address
from pathlib import Path

import pytest

from aegisnet.domain.enums import EventType, RejectReason
from aegisnet.domain.eve.normalizer import (
    UNSUPPORTED_EVENT_TYPES,
    TimestampWindow,
    map_event_type,
    normalize_line,
    normalize_lines,
)
from aegisnet.domain.eve.sanitize import EXCERPT_CHARS
from aegisnet.domain.models import NormalizedEvent, Reject

pytestmark = pytest.mark.unit

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "eve"
NOW = datetime(2026, 9, 5, 12, 0, tzinfo=UTC)


def _lines(name: str) -> list[str]:
    return (FIXTURES / name).read_text(encoding="utf-8").splitlines()


def _event(line: str) -> NormalizedEvent:
    outcome = normalize_line(line, now=NOW)
    assert isinstance(outcome, NormalizedEvent), outcome
    return outcome


def _reject(line: str) -> Reject:
    outcome = normalize_line(line, now=NOW)
    assert isinstance(outcome, Reject), outcome
    return outcome


@pytest.fixture(scope="module")
def benign() -> dict[str, NormalizedEvent]:
    """Every benign fixture line normalises; keyed by pcap_cnt for readable lookups."""
    events = [_event(line) for line in _lines("benign.ndjson")]
    return {str(event.payload["pcap_cnt"]): event for event in events}


def test_every_benign_line_normalises(benign: dict[str, NormalizedEvent]) -> None:
    assert len(benign) == 11
    assert all(len(event.event_hash) == 32 for event in benign.values())
    assert len({event.event_hash for event in benign.values()}) == 11


def test_alert_promotes_signature_http_and_flow_metadata(
    benign: dict[str, NormalizedEvent],
) -> None:
    event = benign["1"]
    assert event.event_type is EventType.alert
    assert event.event_time == datetime(2026, 9, 1, 10, 0, 0, 1, tzinfo=UTC)
    assert (event.src_ip, event.src_port) == (IPv4Address("10.10.0.11"), 51000)
    assert (event.dest_ip, event.dest_port, event.proto, event.app_proto) == (
        IPv4Address("203.0.113.10"),
        80,
        "TCP",
        "http",
    )
    assert (event.sig_signature_id, event.sig_severity) == (9000001, 3)
    assert event.sig_signature == "AEGISNET-SYNTH INFO HTTP request to example.test"
    assert event.sig_category == "Not Suspicious Traffic"
    assert (event.http_host, event.http_url_path) == ("www.example.test", "/")
    assert (event.bytes_toserver, event.bytes_toclient) == (640, 1200)
    assert (event.pkts_toserver, event.pkts_toclient) == (5, 4)
    assert event.payload["alert"]["gid"] == 1


def test_dns_query_answer_and_v3_are_promoted(benign: dict[str, NormalizedEvent]) -> None:
    query, answer, v3 = benign["2"], benign["3"], benign["4"]
    assert (query.dns_query, query.dns_rrtype, query.dns_rcode) == ("cdn.example.test", "A", None)
    assert (answer.dns_query, answer.dns_rrtype, answer.dns_rcode) == (
        "cdn.example.test",
        "A",
        "NOERROR",
    )
    assert answer.flow_id == query.flow_id == 2222222222222222
    assert (v3.dns_query, v3.dns_rrtype) == ("updates.example.test", "AAAA")
    assert answer.payload["dns"]["answers"][0]["rdata"] == "203.0.113.11"


def test_http_flow_tls_fileinfo_anomaly_and_ssh_map_to_their_types(
    benign: dict[str, NormalizedEvent],
) -> None:
    assert benign["5"].event_type is EventType.http
    assert (benign["5"].http_host, benign["5"].http_url_path) == (
        "api.example.com",
        "/api/v1/status",
    )
    flow = benign["6"]
    assert flow.event_type is EventType.flow
    assert (flow.bytes_toserver, flow.bytes_toclient, flow.pkts_toserver, flow.pkts_toclient) == (
        2400,
        9800,
        12,
        9,
    )
    assert flow.payload["tcp"]["state"] == "closed"
    assert benign["7"].event_type is EventType.tls
    assert benign["7"].payload["tls"]["sni"] == "www.example.com"
    assert benign["8"].event_type is EventType.fileinfo
    assert benign["8"].http_url_path == "/assets/app.js"
    assert benign["9"].event_type is EventType.anomaly
    assert benign["10"].event_type is EventType.ssh


def test_unknown_network_event_types_map_to_other_and_keep_their_payload(
    benign: dict[str, NormalizedEvent],
) -> None:
    smb = benign["11"]
    assert smb.event_type is EventType.other
    assert smb.payload["event_type"] == "smb"
    assert smb.payload["smb"]["dialect"] == "3.11"
    assert map_event_type("smb") is EventType.other
    assert map_event_type("dns") is EventType.dns


def test_hostile_lines_are_rejected_for_the_right_reasons() -> None:
    lines = _lines("hostile.ndjson")
    outcomes = [normalize_line(line, now=NOW) for line in lines]

    # Lines 1 and 2 are hostile but well-formed: they are accepted, neutralised.
    dns = outcomes[0]
    assert isinstance(dns, NormalizedEvent)
    assert dns.dns_query == '[2Jevil{"level":"INFO","message":"forged"}.example.test'
    assert dns.dns_rrtype == "A"
    assert "\x1b" not in json.dumps(dns.payload) and "\n" not in json.dumps(dns.payload)
    http = outcomes[1]
    assert isinstance(http, NormalizedEvent)
    assert http.http_host == "' OR 1=1 --evil.example.test"
    assert http.http_url_path == "/..%2f..%2fetc/passwd[31m"
    assert http.payload["http"]["http_user_agent"] == "tab\tkept"

    expected = [
        RejectReason.missing_required,  # no timestamp
        RejectReason.missing_required,  # no event_type
        RejectReason.schema_invalid,  # naive timestamp
        RejectReason.unsupported_event_type,  # stats
        RejectReason.schema_invalid,  # src_ip not an address
        RejectReason.schema_invalid,  # dest_port 70000
        RejectReason.schema_invalid,  # top-level array
        RejectReason.json_parse,  # truncated line
        RejectReason.timestamp_out_of_range,  # 1999
        RejectReason.timestamp_out_of_range,  # 2036
    ]
    rejects = outcomes[2:]
    assert [r.reason for r in rejects if isinstance(r, Reject)] == expected
    assert len(rejects) == len(expected)


def test_reject_details_name_fields_but_never_echo_input_values() -> None:
    reject = _reject(
        '{"timestamp":"2026-09-01T10:00:05+0000","event_type":"flow","src_ip":"not-an-ip"}'
    )
    assert reject.reason is RejectReason.schema_invalid
    assert "src_ip" in reject.detail
    assert "not-an-ip" not in reject.detail
    missing = _reject('{"src_ip":"10.0.0.1"}')
    assert missing.detail == "missing required field(s): event_type, timestamp"


def test_raw_excerpt_is_bounded_and_neutralised() -> None:
    line = '{"event_type":"flow","note":"\x1b[2J' + "a" * 5000 + '"}'
    reject = _reject(line)
    assert reject.raw_excerpt is not None
    assert len(reject.raw_excerpt) == EXCERPT_CHARS
    assert "\x1b" not in reject.raw_excerpt


def test_timestamp_window_is_relative_to_the_supplied_clock() -> None:
    line = '{"timestamp":"2026-09-01T10:00:00+0000","event_type":"flow"}'
    assert isinstance(normalize_line(line, now=NOW), NormalizedEvent)
    too_old = normalize_line(line, now=NOW + timedelta(days=3651))
    assert isinstance(too_old, Reject) and too_old.reason is RejectReason.timestamp_out_of_range
    future = normalize_line(line, now=datetime(2026, 8, 30, tzinfo=UTC))
    assert isinstance(future, Reject) and future.reason is RejectReason.timestamp_out_of_range
    tight = TimestampWindow(max_past=timedelta(hours=1), max_future=timedelta(0))
    at_edge = normalize_line(line, now=datetime(2026, 9, 1, 11, 0, tzinfo=UTC), window=tight)
    assert isinstance(at_edge, NormalizedEvent)
    assert isinstance(
        normalize_line(line, now=datetime(2026, 9, 1, 11, 0, 1, tzinfo=UTC), window=tight), Reject
    )


def test_a_naive_clock_is_a_programming_error() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        normalize_line("{}", now=datetime(2026, 9, 5))


def test_same_line_twice_yields_the_same_hash_and_different_lines_differ() -> None:
    lines = _lines("benign.ndjson")
    first = _event(lines[1]).event_hash
    assert first == _event(lines[1]).event_hash
    assert first == _event(lines[1] + "\r\n").event_hash
    assert first != _event(lines[2]).event_hash


def test_normalize_lines_numbers_from_one_and_skips_blank_lines() -> None:
    lines = ["", _lines("benign.ndjson")[0], "   ", "not json"]
    outcomes = normalize_lines(lines, now=NOW)
    assert [number for number, _ in outcomes] == [2, 4]
    assert isinstance(outcomes[0][1], NormalizedEvent)
    assert isinstance(outcomes[1][1], Reject)


def test_unsupported_types_are_exactly_the_sensor_housekeeping_records() -> None:
    assert frozenset({"stats", "engine"}) == UNSUPPORTED_EVENT_TYPES
