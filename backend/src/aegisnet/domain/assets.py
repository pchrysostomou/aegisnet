"""Asset inventory rules (FR-3): validation, CIDR overlap, and IP-to-asset resolution.

Pure. The SQL adapter expresses resolution as an ``ORDER BY``; the functions here are the
reference implementation that the in-memory fake and the unit tests use, and they decide
ties exactly as ``docs/data-model.md`` states: the most specific matching CIDR wins, ties
go to the primary network, then to the oldest asset.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_network
from typing import Final
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aegisnet.domain.enums import AssetEnvironment

IPNetwork = IPv4Network | IPv6Network
IPAddress = IPv4Address | IPv6Address

HOSTNAME: Final = re.compile(
    r"^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$"
)
TAG: Final = re.compile(r"^[a-z0-9-]{1,32}$")
MAX_TAGS: Final = 20
MAX_NETWORKS: Final = 32
MAX_OWNER_CHARS: Final = 128
MAX_DESCRIPTION_CHARS: Final = 1000
MIN_CRITICALITY: Final = 1
MAX_CRITICALITY: Final = 5
MAX_BULK: Final = 500


def normalise_hostname(value: str | None) -> str | None:
    if value is None:
        return None
    lowered = value.strip().lower()
    if not HOSTNAME.match(lowered):
        raise ValueError("hostname must be a lowercase DNS name")
    return lowered


def normalise_tags(value: list[str] | None) -> list[str] | None:
    if value is None:
        return None
    cleaned = [tag.strip().lower() for tag in value]
    if any(not TAG.match(tag) for tag in cleaned):
        raise ValueError("tags must match [a-z0-9-]{1,32}")
    if len(set(cleaned)) != len(cleaned):
        raise ValueError("tags must be unique")
    return cleaned


def check_networks(networks: list[NetworkSpec] | None) -> None:
    if networks is None:
        return
    cidrs = [network.cidr for network in networks]
    if len(set(cidrs)) != len(cidrs):
        raise ValueError("networks must be unique")
    if sum(1 for network in networks if network.is_primary) > 1:
        raise ValueError("at most one network may be primary")


class NetworkSpec(BaseModel):
    """One CIDR. Host bits must be zero (``192.0.2.10/32`` is fine, ``/24`` on it is not)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    cidr: IPNetwork
    is_primary: bool = False

    @field_validator("cidr", mode="before")
    @classmethod
    def _strict_network(cls, value: object) -> object:
        if isinstance(value, str):
            try:
                return ip_network(value.strip(), strict=True)
            except ValueError as error:
                raise ValueError("cidr must be a network with no host bits set") from error
        return value


class AssetSpec(BaseModel):
    """What it takes to create an asset (``POST /api/v1/assets`` body, seed file entry)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    hostname: str | None = None
    environment: AssetEnvironment
    owner: str | None = Field(default=None, max_length=MAX_OWNER_CHARS)
    criticality: int = Field(default=3, ge=MIN_CRITICALITY, le=MAX_CRITICALITY)
    tags: list[str] = Field(default_factory=list, max_length=MAX_TAGS)
    description: str | None = Field(default=None, max_length=MAX_DESCRIPTION_CHARS)
    networks: list[NetworkSpec] = Field(default_factory=list, max_length=MAX_NETWORKS)

    @field_validator("hostname")
    @classmethod
    def _hostname(cls, value: str | None) -> str | None:
        return normalise_hostname(value)

    @field_validator("tags")
    @classmethod
    def _tags(cls, value: list[str]) -> list[str]:
        cleaned = normalise_tags(value)
        return cleaned if cleaned is not None else []

    @model_validator(mode="after")
    def _networks(self) -> AssetSpec:
        check_networks(self.networks)
        return self


class AssetPatch(BaseModel):
    """Partial update (``PATCH``). Only the fields given change; ``networks`` replaces all."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    hostname: str | None = None
    environment: AssetEnvironment | None = None
    owner: str | None = Field(default=None, max_length=MAX_OWNER_CHARS)
    criticality: int | None = Field(default=None, ge=MIN_CRITICALITY, le=MAX_CRITICALITY)
    tags: list[str] | None = Field(default=None, max_length=MAX_TAGS)
    description: str | None = Field(default=None, max_length=MAX_DESCRIPTION_CHARS)
    networks: list[NetworkSpec] | None = Field(default=None, max_length=MAX_NETWORKS)
    is_active: bool | None = None

    @field_validator("hostname")
    @classmethod
    def _hostname(cls, value: str | None) -> str | None:
        return normalise_hostname(value)

    @field_validator("tags")
    @classmethod
    def _tags(cls, value: list[str] | None) -> list[str] | None:
        return normalise_tags(value)

    @model_validator(mode="after")
    def _networks(self) -> AssetPatch:
        check_networks(self.networks)
        return self

    def changes(self) -> dict[str, object]:
        """The fields the caller actually supplied, for a before/after audit diff."""
        return {key: getattr(self, key) for key in sorted(self.model_fields_set)}


class AssetError(Exception):
    """Base class for asset inventory failures; messages are safe to show to a caller."""


class AssetNotFoundError(AssetError):
    pass


class HostnameConflictError(AssetError):
    pass


class BulkTooLargeError(AssetError):
    pass


class NetworkOverlapError(AssetError):
    def __init__(self, overlaps: list[Overlap]) -> None:
        self.overlaps = overlaps
        described = "; ".join(f"{item.cidr} overlaps {item.other_cidr}" for item in overlaps[:5])
        super().__init__(f"network overlap: {described}")


@dataclass(frozen=True, slots=True)
class NetworkRecord:
    """A stored CIDR with the asset facts resolution needs."""

    asset_id: UUID
    cidr: IPNetwork
    is_primary: bool
    asset_created_at: datetime


@dataclass(frozen=True, slots=True)
class Overlap:
    cidr: IPNetwork
    other_asset_id: UUID
    other_cidr: IPNetwork


def find_overlaps(
    candidates: Iterable[IPNetwork],
    existing: Iterable[NetworkRecord],
    *,
    exclude_asset_id: UUID | None = None,
) -> list[Overlap]:
    """CIDRs that overlap a network of a *different* asset. ``exclude_asset_id`` skips the
    asset being updated, so its own networks never conflict with their replacement."""
    others = [record for record in existing if record.asset_id != exclude_asset_id]
    overlaps: list[Overlap] = []
    for cidr in candidates:
        for record in others:
            if cidr.version == record.cidr.version and cidr.overlaps(record.cidr):
                overlaps.append(Overlap(cidr, record.asset_id, record.cidr))
    return overlaps


def find_internal_overlaps(networks_by_index: Iterable[Iterable[IPNetwork]]) -> list[Overlap]:
    """Overlaps *between* the entries of one bulk request, before anything is stored."""
    seen: list[tuple[int, IPNetwork]] = []
    overlaps: list[Overlap] = []
    for index, cidrs in enumerate(networks_by_index):
        for cidr in cidrs:
            for other_index, other in seen:
                if other_index != index and cidr.version == other.version and cidr.overlaps(other):
                    overlaps.append(Overlap(cidr, UUID(int=other_index), other))
            seen.append((index, cidr))
    return overlaps


def resolve_ip(address: IPAddress, networks: Iterable[NetworkRecord]) -> NetworkRecord | None:
    """Most specific matching CIDR wins; ties go to the primary network, then to the
    oldest asset. Returns ``None`` when nothing matches (the caller reports ``unknown``)."""
    matching = [
        record
        for record in networks
        if record.cidr.version == address.version and address in record.cidr
    ]
    if not matching:
        return None
    return max(
        matching,
        key=lambda record: (
            record.cidr.prefixlen,
            record.is_primary,
            -record.asset_created_at.timestamp(),
        ),
    )
