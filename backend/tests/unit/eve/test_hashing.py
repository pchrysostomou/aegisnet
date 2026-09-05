"""ADR-005: the canonical event hash is stable, versioned and sensitive to what matters."""

from __future__ import annotations

import hashlib
import json
from typing import Any

import pytest

from aegisnet.domain.eve.hashing import HASH_BYTES, HASH_VERSION, event_hash, hash_material
from aegisnet.domain.eve.sanitize import clean_record
from aegisnet.domain.eve.schema import EveRecord

pytestmark = pytest.mark.unit

RAW: dict[str, Any] = {
    "timestamp": "2026-09-01T10:00:01.000000+0000",
    "flow_id": 2222222222222222,
    "pcap_cnt": 2,
    "in_iface": "lab0",
    "event_type": "dns",
    "src_ip": "10.10.0.12",
    "src_port": 40001,
    "dest_ip": "10.10.0.53",
    "dest_port": 53,
    "proto": "UDP",
    "dns": {"version": 2, "type": "query", "id": 4242, "rrname": "cdn.example.test", "rrtype": "A"},
}


def _digest(raw: dict[str, Any]) -> bytes:
    sanitized = clean_record(raw)
    return event_hash(hash_material(EveRecord.model_validate(sanitized), sanitized))


def test_digest_is_thirty_two_bytes_and_deterministic() -> None:
    first, second = _digest(RAW), _digest(json.loads(json.dumps(RAW)))
    assert len(first) == HASH_BYTES
    assert first == second


def test_equivalent_spellings_hash_identically() -> None:
    same_offset_with_colon = {**RAW, "timestamp": "2026-09-01T10:00:01.000000+00:00"}
    same_instant_other_zone = {**RAW, "timestamp": "2026-09-01T11:00:01.000000+0100"}
    assert _digest(RAW) == _digest(same_offset_with_colon) == _digest(same_instant_other_zone)

    ipv6 = {**RAW, "src_ip": "2001:db8::1"}
    ipv6_long = {**RAW, "src_ip": "2001:0db8:0000:0000:0000:0000:0000:0001"}
    assert _digest(ipv6) == _digest(ipv6_long)


@pytest.mark.parametrize(
    "change",
    [
        {"timestamp": "2026-09-01T10:00:01.000001+0000"},
        {"src_port": 40002},
        {"event_type": "http"},
        {"flow_id": 1},
        {"dns": {**RAW["dns"], "rrname": "evil.example.test"}},
        {"pcap_cnt": 3},
    ],
)
def test_material_fields_change_the_digest(change: dict[str, Any]) -> None:
    assert _digest({**RAW, **change}) != _digest(RAW)


def test_keys_outside_the_material_do_not_change_the_digest() -> None:
    assert _digest({**RAW, "vlan": [7], "note": "annotation"}) == _digest(RAW)


def test_missing_common_fields_are_omitted_rather_than_written_as_null() -> None:
    sanitized = clean_record({"timestamp": "2026-09-01T10:00:01+0000", "event_type": "x"})
    material = hash_material(EveRecord.model_validate(sanitized), sanitized)
    assert material == {"timestamp": "2026-09-01T10:00:01.000000+00:00", "event_type": "x"}


def test_digest_is_the_versioned_sha256_of_canonical_json() -> None:
    sanitized = clean_record(RAW)
    material = hash_material(EveRecord.model_validate(sanitized), sanitized)
    canonical = json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    expected = hashlib.sha256(
        f"aegisnet-event-hash-v{HASH_VERSION}\n".encode() + canonical.encode()
    ).digest()
    assert event_hash(material) == expected
