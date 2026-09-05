"""The two normalisation semantics the isolated lab forced (docs/evaluation.md §9, ADR-022).

**L-F1.** A flow record is stamped when Suricata's flow manager emits it, which is when the
flow ended or timed out — not when the conversation happened. Every rule that reasons about
time (D-004's intervals above all) needs the latter, so a flow event is filed under
``flow.start`` when the record carries one.

**L-F2.** EVE v3 puts an ``rcode`` on a DNS *request* as well as on the response. Reading
"has an rcode" as "is an answer" made every v3 record look like an answer, so no query name
was ever tallied and every lookup was attributed to the resolver. Direction now comes from
the record's own ``type``.

Both were invisible from generated data, because the generators had the same assumptions in
them. These tests are hand-built lines, so they hold whatever the generators do next.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from aegisnet.domain.enums import EventType, RejectReason
from aegisnet.domain.eve.normalizer import normalize_line
from aegisnet.domain.eve.schema import parse_suricata_time
from aegisnet.domain.models import NormalizedEvent, Reject

pytestmark = pytest.mark.unit

NOW = datetime(2026, 9, 5, 12, 0, tzinfo=UTC)
STARTED = datetime(2026, 9, 5, 11, 30, 0, tzinfo=UTC)
EMITTED = datetime(2026, 9, 5, 11, 35, 12, tzinfo=UTC)


def _suricata(moment: datetime) -> str:
    """The shape Suricata writes: microseconds and a colon-less offset."""
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f+0000")


def _flow_line(**flow: Any) -> str:
    record = {
        "timestamp": _suricata(EMITTED),
        "event_type": "flow",
        "flow_id": 1234567890,
        "src_ip": "10.10.0.5",
        "src_port": 40000,
        "dest_ip": "203.0.113.10",
        "dest_port": 443,
        "proto": "TCP",
        "flow": {
            "pkts_toserver": 10,
            "pkts_toclient": 8,
            "bytes_toserver": 900,
            "bytes_toclient": 1200,
            "state": "closed",
            "reason": "timeout",
            **flow,
        },
    }
    return json.dumps(record)


def _dns_line(**dns: Any) -> str:
    record = {
        "timestamp": _suricata(EMITTED),
        "event_type": "dns",
        "flow_id": 222,
        "src_ip": "10.10.0.5",
        "src_port": 51000,
        "dest_ip": "10.10.0.53",
        "dest_port": 53,
        "proto": "UDP",
        "dns": dns,
    }
    return json.dumps(record)


def _event(line: str) -> NormalizedEvent:
    outcome = normalize_line(line, now=NOW)
    assert isinstance(outcome, NormalizedEvent), outcome
    return outcome


# ---------------------------------------------------------------- L-F1, flow event time


def test_a_flow_event_is_filed_under_the_instant_the_flow_began() -> None:
    event = _event(_flow_line(start=_suricata(STARTED), end=_suricata(EMITTED)))
    assert event.event_time == STARTED, "the conversation, not the sensor's announcement"
    assert event.payload["timestamp"].startswith("2026-09-05T11:35:12"), "emission time kept"


def test_an_alert_carrying_a_flow_block_keeps_its_own_timestamp() -> None:
    """Only flow records are emitted long after the fact. An alert's timestamp is the moment
    the signature matched, which is exactly what it should be filed under."""
    line = json.dumps(
        {
            "timestamp": _suricata(EMITTED),
            "event_type": "alert",
            "src_ip": "10.10.0.5",
            "dest_ip": "203.0.113.10",
            "proto": "TCP",
            "alert": {"signature": "AEGISNET-LAB marker", "signature_id": 9100001, "severity": 3},
            "flow": {"start": _suricata(STARTED), "bytes_toserver": 10},
        }
    )
    event = _event(line)
    assert event.event_type is EventType.alert
    assert event.event_time == EMITTED


@pytest.mark.parametrize(
    "start",
    [None, "", "not a timestamp", "2026-09-05T11:30:00", "2026-09-05 11:30:00+00:00Z"],
    ids=["absent", "empty", "garbage", "naive", "malformed"],
)
def test_a_flow_start_that_cannot_be_read_falls_back_to_the_record_timestamp(
    start: str | None,
) -> None:
    """A flow record with an unreadable start is still a usable flow record. It is filed under
    the only instant available rather than refused."""
    flow: dict[str, Any] = {} if start is None else {"start": start}
    assert _event(_flow_line(**flow)).event_time == EMITTED


def test_a_flow_start_outside_the_freshness_window_is_refused() -> None:
    """T-1.7 applies to whichever instant the event is filed under, not only to the one the
    record announces: a sensor whose flow start is decades off is not one to trust quietly."""
    outcome = normalize_line(_flow_line(start=_suricata(NOW - timedelta(days=4000))), now=NOW)
    assert isinstance(outcome, Reject)
    assert outcome.reason is RejectReason.timestamp_out_of_range
    assert "flow.start" in outcome.detail


def test_the_record_timestamp_is_still_checked_even_when_the_flow_start_is_fine() -> None:
    line = json.dumps(
        {
            "timestamp": _suricata(NOW + timedelta(days=2)),
            "event_type": "flow",
            "src_ip": "10.10.0.5",
            "dest_ip": "203.0.113.10",
            "proto": "TCP",
            "flow": {"start": _suricata(STARTED)},
        }
    )
    outcome = normalize_line(line, now=NOW)
    assert isinstance(outcome, Reject)
    assert outcome.reason is RejectReason.timestamp_out_of_range
    assert outcome.detail.startswith("timestamp ")


def test_deduplication_is_untouched_by_the_change() -> None:
    """The hash is built from the record's own timestamp, so filing an event under a different
    instant cannot make the same line hash twice — or two different lines collide."""
    line = _flow_line(start=_suricata(STARTED))
    first, second = _event(line), _event(line)
    assert first.event_hash == second.event_hash
    assert first.event_time == STARTED != EMITTED
    other = _event(_flow_line(start=_suricata(STARTED - timedelta(seconds=1))))
    assert other.event_hash != first.event_hash, "a different start is a different record"


# ---------------------------------------------------------------- L-F2, DNS direction


@pytest.mark.parametrize(
    ("dns", "expected"),
    [
        ({"version": 2, "type": "query", "rrname": "a.example.test", "rrtype": "A"}, None),
        (
            {
                "version": 2,
                "type": "answer",
                "rrname": "a.example.test",
                "rrtype": "A",
                "rcode": "NOERROR",
            },
            "NOERROR",
        ),
        (
            {
                "version": 3,
                "type": "request",
                "rcode": "NOERROR",
                "queries": [{"rrname": "a.example.test", "rrtype": "A"}],
            },
            None,
        ),
        (
            {
                "version": 3,
                "type": "response",
                "rcode": "NXDOMAIN",
                "queries": [{"rrname": "a.example.test", "rrtype": "A"}],
            },
            "NXDOMAIN",
        ),
    ],
    ids=["v2-query", "v2-answer", "v3-request", "v3-response"],
)
def test_only_a_reply_carries_a_response_code(dns: dict[str, Any], expected: str | None) -> None:
    """The v3 request is the case that mattered: Suricata puts an rcode on it, and reading
    that as "this is an answer" is what blinded D-003 to every real lookup."""
    event = _event(_dns_line(**dns))
    assert event.dns_rcode == expected
    assert event.dns_query == "a.example.test", "the name is promoted either way"


def test_a_record_with_no_type_falls_back_to_what_it_carries() -> None:
    """Older and hand-written shapes omit `type`; then the rcode is the only signal there is."""
    assert _event(_dns_line(rrname="a.example.test", rcode="NOERROR")).dns_rcode == "NOERROR"
    assert _event(_dns_line(rrname="a.example.test")).dns_rcode is None


def test_an_unfamiliar_direction_is_treated_as_a_question() -> None:
    """A `type` nobody recognises is not evidence of an answer, and treating it as one is the
    failure this whole change is about."""
    event = _event(_dns_line(type="probe", rrname="a.example.test", rcode="NOERROR"))
    assert event.dns_rcode is None


# ---------------------------------------------------------------- the parser itself


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("2026-09-05T11:30:00.000000+0000", STARTED),
        ("2026-09-05T11:30:00.000000+00:00", STARTED),
        ("2026-09-05T12:30:00.000000+0100", STARTED),
        ("  2026-09-05T11:30:00.000000+0000  ", STARTED),
        (None, None),
        ("", None),
        ("2026-09-05T11:30:00", None),
        ("yesterday", None),
        ("2026-13-45T99:99:99+0000", None),
    ],
    ids=[
        "suricata-offset",
        "iso-offset",
        "other-zone",
        "padded",
        "absent",
        "empty",
        "naive",
        "prose",
        "impossible",
    ],
)
def test_the_suricata_time_parser_is_strict_about_offsets_and_forgiving_about_the_rest(
    text: str | None, expected: datetime | None
) -> None:
    """Every sub-second field Suricata writes as text goes through this. It refuses a naive
    instant — guessing a zone is how a detector ends up an hour out — and returns None rather
    than raising for anything it cannot read, because its callers all have a fallback."""
    assert parse_suricata_time(text) == expected
