"""Asset rules: validation, cross-asset overlap, and most-specific-CIDR resolution."""

from __future__ import annotations

from datetime import UTC, datetime
from ipaddress import ip_address, ip_network
from uuid import UUID

import pytest
from pydantic import ValidationError

from aegisnet.domain.assets import (
    AssetPatch,
    AssetSpec,
    NetworkRecord,
    NetworkSpec,
    find_internal_overlaps,
    find_overlaps,
    resolve_ip,
)
from aegisnet.domain.enums import AssetEnvironment

pytestmark = pytest.mark.unit

A, B, C = UUID(int=1), UUID(int=2), UUID(int=3)
T0 = datetime(2026, 9, 1, tzinfo=UTC)
T1 = datetime(2026, 9, 2, tzinfo=UTC)


def _spec(**overrides: object) -> AssetSpec:
    base: dict[str, object] = {"hostname": "ws-10.lab.example.test", "environment": "lab"}
    return AssetSpec.model_validate({**base, **overrides})


def test_spec_normalises_hostname_and_tags() -> None:
    spec = _spec(hostname="  WS-10.Lab.Example.TEST ", tags=["Web", " DMZ "])
    assert spec.hostname == "ws-10.lab.example.test"
    assert spec.tags == ["web", "dmz"]
    assert spec.criticality == 3 and spec.networks == []


@pytest.mark.parametrize(
    "bad",
    [
        {"hostname": "-bad"},
        {"hostname": "has space"},
        {"hostname": "a" * 254},
        {"tags": ["ok", "Bad!"]},
        {"tags": ["dup", "dup"]},
        {"tags": [f"t{i}" for i in range(21)]},
        {"criticality": 0},
        {"criticality": 6},
        {"environment": "production"},
        {"owner": "o" * 129},
        {"networks": [{"cidr": "10.0.0.1/24"}]},
        {"networks": [{"cidr": "10.0.0.0/24"}, {"cidr": "10.0.0.0/24"}]},
        {
            "networks": [
                {"cidr": "10.0.0.0/24", "is_primary": True},
                {"cidr": "10.1.0.0/24", "is_primary": True},
            ]
        },
        {"networks": [{"cidr": "10.0.0.0/24", "extra": 1}]},
        {"unknown": "field"},
    ],
)
def test_spec_rejects_bad_values(bad: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        _spec(**bad)


def test_network_spec_parses_strict_cidrs() -> None:
    assert NetworkSpec.model_validate({"cidr": " 192.0.2.10/32 "}).cidr == ip_network(
        "192.0.2.10/32"
    )
    assert NetworkSpec.model_validate({"cidr": "2001:db8::/64"}).cidr.version == 6


def test_patch_tracks_which_fields_were_supplied() -> None:
    patch = AssetPatch.model_validate({"criticality": 5, "tags": ["Core"]})
    assert patch.changes() == {"criticality": 5, "tags": ["core"]}
    assert AssetPatch().changes() == {}
    with pytest.raises(ValidationError):
        AssetPatch.model_validate({"is_active": "maybe"})


def _records() -> list[NetworkRecord]:
    return [
        NetworkRecord(A, ip_network("10.10.0.0/24"), True, T0),
        NetworkRecord(B, ip_network("10.10.0.11/32"), True, T1),
        NetworkRecord(C, ip_network("2001:db8::/64"), False, T0),
    ]


def test_overlaps_are_detected_across_assets_but_not_against_the_excluded_one() -> None:
    hits = find_overlaps([ip_network("10.10.0.0/16")], _records())
    assert {hit.other_asset_id for hit in hits} == {A, B}
    assert find_overlaps([ip_network("10.10.0.0/16")], _records(), exclude_asset_id=A) != []
    assert find_overlaps([ip_network("10.10.0.11/32")], _records(), exclude_asset_id=B) == [
        *find_overlaps([ip_network("10.10.0.11/32")], [_records()[0]])
    ]
    assert find_overlaps([ip_network("192.0.2.0/24")], _records()) == []
    assert find_overlaps([ip_network("2001:db8::1/128")], _records())[0].other_asset_id == C


def test_internal_overlaps_only_between_different_entries() -> None:
    same_entry = [[ip_network("10.0.0.0/24"), ip_network("10.0.0.1/32")]]
    assert find_internal_overlaps(same_entry) == []
    across = [[ip_network("10.0.0.0/24")], [ip_network("10.0.0.128/25")]]
    (hit,) = find_internal_overlaps(across)
    assert (hit.cidr, hit.other_cidr) == (ip_network("10.0.0.128/25"), ip_network("10.0.0.0/24"))


def test_resolution_prefers_the_most_specific_then_primary_then_oldest() -> None:
    records = _records()
    assert resolve_ip(ip_address("10.10.0.11"), records) is records[1]  # /32 beats /24
    assert resolve_ip(ip_address("10.10.0.12"), records) is records[0]
    assert resolve_ip(ip_address("10.99.0.1"), records) is None
    assert resolve_ip(ip_address("2001:db8::7"), records) is records[2]

    tie = [
        NetworkRecord(A, ip_network("10.0.0.0/24"), False, T0),
        NetworkRecord(B, ip_network("10.0.0.0/24"), True, T1),
    ]
    assert resolve_ip(ip_address("10.0.0.5"), tie).asset_id == B  # primary wins the tie
    oldest = [
        NetworkRecord(A, ip_network("10.0.0.0/24"), False, T1),
        NetworkRecord(B, ip_network("10.0.0.0/24"), False, T0),
    ]
    assert resolve_ip(ip_address("10.0.0.5"), oldest).asset_id == B  # then the oldest asset


def test_environment_enum_round_trips() -> None:
    assert _spec(environment="prod_sim").environment is AssetEnvironment.prod_sim
