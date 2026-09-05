"""EVE schema: what is required, what is typed, what is tolerated."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone
from ipaddress import IPv4Address, IPv6Address

import pytest
from pydantic import ValidationError

from aegisnet.domain.eve.schema import EveRecord

pytestmark = pytest.mark.unit

BASE = {"event_type": "flow", "src_ip": "10.10.0.11", "dest_ip": "203.0.113.10"}


@pytest.mark.parametrize(
    "raw",
    [
        "2026-09-01T10:00:00.000001+0000",
        "2026-09-01T10:00:00.000001+00:00",
        "2026-09-01T10:00:00.000001Z",
        "2026-09-01T11:00:00.000001+0100",
        "2026-09-01T11:00:00.000001+01:00",
    ],
)
def test_timestamp_offsets_are_accepted_and_normalised_to_utc(raw: str) -> None:
    record = EveRecord.model_validate({**BASE, "timestamp": raw})
    assert record.timestamp == datetime(2026, 9, 1, 10, 0, 0, 1, tzinfo=UTC)
    assert record.timestamp.tzinfo is UTC


def test_datetime_objects_are_accepted_when_aware() -> None:
    plus_two = datetime(2026, 9, 1, 12, 0, tzinfo=timezone(timedelta(hours=2)))
    record = EveRecord.model_validate({**BASE, "timestamp": plus_two})
    assert record.timestamp == datetime(2026, 9, 1, 10, 0, tzinfo=UTC)


@pytest.mark.parametrize("raw", ["2026-09-01T10:00:00", "2026-09-01", "yesterday", "", None])
def test_naive_or_malformed_timestamps_are_refused(raw: object) -> None:
    with pytest.raises(ValidationError):
        EveRecord.model_validate({**BASE, "timestamp": raw})


def test_an_epoch_integer_is_accepted_as_utc() -> None:
    """pydantic reads a bare number as seconds since the epoch, which is unambiguous."""
    record = EveRecord.model_validate({**BASE, "timestamp": 1_756_720_800})
    assert record.timestamp == datetime(2025, 9, 1, 10, 0, tzinfo=UTC)


def test_timestamp_and_event_type_are_the_only_required_fields() -> None:
    with pytest.raises(ValidationError) as excinfo:
        EveRecord.model_validate({})
    missing = {
        tuple(error["loc"]) for error in excinfo.value.errors() if error["type"] == "missing"
    }
    assert missing == {("timestamp",), ("event_type",)}
    minimal = EveRecord.model_validate({"timestamp": "2026-09-01T10:00:00+0000", "event_type": "x"})
    assert minimal.src_ip is None and minimal.flow is None


def test_addresses_are_parsed_into_ip_objects() -> None:
    record = EveRecord.model_validate(
        {**BASE, "timestamp": "2026-09-01T10:00:00+0000", "src_ip": "2001:db8::1"}
    )
    assert record.src_ip == IPv6Address("2001:db8::1")
    assert record.dest_ip == IPv4Address("203.0.113.10")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("src_ip", "999.1.1.1"),
        ("dest_ip", "example.test"),
        ("src_port", -1),
        ("dest_port", 65536),
        ("flow_id", -5),
        ("event_type", ""),
        ("event_type", "x" * 65),
        ("alert", {"severity": -1}),
        ("dns", {"tx_id": -1}),
        ("http", {"status": "two hundred"}),
        ("flow", {"bytes_toserver": -1}),
        ("fileinfo", {"size": -1}),
    ],
)
def test_typed_fields_reject_bad_values(field: str, value: object) -> None:
    with pytest.raises(ValidationError):
        EveRecord.model_validate({**BASE, "timestamp": "2026-09-01T10:00:00+0000", field: value})


def test_unknown_keys_are_kept_at_every_level() -> None:
    record = EveRecord.model_validate(
        {
            **BASE,
            "timestamp": "2026-09-01T10:00:00+0000",
            "community_id": "1:abc",
            "vlan": [100],
            "http": {"hostname": "www.example.test", "xff": "10.0.0.1"},
        }
    )
    assert record.model_extra == {"vlan": [100]}
    assert record.http is not None
    assert record.http.hostname == "www.example.test"
    assert record.http.model_extra == {"xff": "10.0.0.1"}


def test_dns_v3_queries_list_is_typed() -> None:
    record = EveRecord.model_validate(
        {
            **BASE,
            "timestamp": "2026-09-01T10:00:00+0000",
            "dns": {"version": 3, "queries": [{"rrname": "a.example.test", "rrtype": "AAAA"}]},
        }
    )
    assert record.dns is not None and record.dns.queries is not None
    assert record.dns.queries[0].rrname == "a.example.test"


def test_records_are_immutable() -> None:
    record = EveRecord.model_validate({**BASE, "timestamp": "2026-09-01T10:00:00+0000"})
    with pytest.raises(ValidationError):
        record.event_type = "changed"  # type: ignore[misc]
