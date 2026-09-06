"""Asset inventory use-cases (FR-3): create, bulk seed, read, update, deactivate, resolve.

Overlap and hostname checks run here, against the store's current networks, before a
write; the store then enforces the hostname unique index as the last line. The IP
resolution rule itself is the store's query (and, in tests, the pure ``resolve_ip``).
Mutations are audited by the routes, which are where the authenticated actor is known.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from aegisnet.domain.assets import (
    MAX_BULK,
    AssetNotFoundError,
    AssetPatch,
    AssetSpec,
    BulkTooLargeError,
    HostnameConflictError,
    IPAddress,
    IPNetwork,
    NetworkOverlapError,
    find_internal_overlaps,
    find_overlaps,
)
from aegisnet.domain.pagination import check_limit, decode_time_id
from aegisnet.domain.ports import AssetFilter, AssetRecord, AssetStore, Page, ResolvedAsset


def utc_now() -> datetime:
    return datetime.now(tz=UTC)


@dataclass(frozen=True, slots=True)
class SeedResult:
    created: int
    updated: int


class AssetService:
    def __init__(self, store: AssetStore, *, clock: Callable[[], datetime] = utc_now) -> None:
        self._store = store
        self._clock = clock

    # ---------------------------------------------------------------- reads
    async def get(self, asset_id: UUID) -> AssetRecord:
        record = await self._store.get(asset_id)
        if record is None:
            raise AssetNotFoundError("unknown asset")
        return record

    async def list(self, query: AssetFilter) -> Page[AssetRecord]:
        check_limit(query.limit)
        if query.cursor is not None:
            decode_time_id(query.cursor)
        return await self._store.list(query)

    async def resolve(self, address: IPAddress) -> ResolvedAsset | None:
        """Most specific CIDR wins; ``None`` means an unknown endpoint, never an error."""
        return await self._store.resolve(address)

    # ---------------------------------------------------------------- writes
    async def create(self, spec: AssetSpec) -> AssetRecord:
        await self._check_hostname_free(spec.hostname)
        await self._check_overlaps([n.cidr for n in spec.networks])
        return await self._store.create(spec, self._clock())

    async def bulk_create(self, specs: Sequence[AssetSpec]) -> tuple[AssetRecord, ...]:
        """Atomic: every asset is stored or none is."""
        if len(specs) > MAX_BULK:
            raise BulkTooLargeError(f"at most {MAX_BULK} assets per request")
        hostnames = [spec.hostname for spec in specs if spec.hostname]
        if len(set(hostnames)) != len(hostnames):
            raise HostnameConflictError("duplicate hostname in request")
        internal = find_internal_overlaps([n.cidr for n in spec.networks] for spec in specs)
        if internal:
            raise NetworkOverlapError(internal)
        for hostname in hostnames:
            await self._check_hostname_free(hostname)
        await self._check_overlaps([n.cidr for spec in specs for n in spec.networks])
        return await self._store.create_many(specs, self._clock())

    async def seed(self, specs: Sequence[AssetSpec]) -> SeedResult:
        """Idempotent seeding by hostname: new hostnames are created atomically, existing
        ones are updated in place with the spec's fields and networks."""
        if any(spec.hostname is None for spec in specs):
            raise HostnameConflictError("every seeded asset needs a hostname")
        new: list[AssetSpec] = []
        existing: list[tuple[AssetRecord, AssetSpec]] = []
        for spec in specs:
            assert spec.hostname is not None
            record = await self._store.get_by_hostname(spec.hostname)
            if record is None:
                new.append(spec)
            else:
                existing.append((record, spec))
        for record, spec in existing:
            patch = AssetPatch(
                environment=spec.environment,
                owner=spec.owner,
                criticality=spec.criticality,
                tags=list(spec.tags),
                description=spec.description,
                networks=list(spec.networks),
                is_active=True,
            )
            await self.update(record.id, patch)
        if new:
            await self.bulk_create(new)
        return SeedResult(created=len(new), updated=len(existing))

    async def update(self, asset_id: UUID, patch: AssetPatch) -> AssetRecord:
        current = await self.get(asset_id)
        if "hostname" in patch.model_fields_set and patch.hostname != current.hostname:
            await self._check_hostname_free(patch.hostname)
        if patch.networks is not None:
            await self._check_overlaps([n.cidr for n in patch.networks], exclude_asset_id=asset_id)
        updated = await self._store.update(asset_id, patch, self._clock())
        if updated is None:  # pragma: no cover - the row existed a moment ago
            raise AssetNotFoundError("unknown asset")
        return updated

    async def deactivate(self, asset_id: UUID) -> AssetRecord:
        """Soft delete (``DELETE /assets/{id}``): historical links stay intact."""
        await self.get(asset_id)
        record = await self._store.deactivate(asset_id, self._clock())
        if record is None:  # pragma: no cover - the row existed a moment ago
            raise AssetNotFoundError("unknown asset")
        return record

    # ---------------------------------------------------------------- checks
    async def _check_hostname_free(self, hostname: str | None) -> None:
        if hostname is not None and await self._store.get_by_hostname(hostname) is not None:
            raise HostnameConflictError("hostname already exists")

    async def _check_overlaps(
        self, cidrs: Sequence[IPNetwork], *, exclude_asset_id: UUID | None = None
    ) -> None:
        if not cidrs:
            return
        existing = await self._store.networks(active_only=True)
        overlaps = find_overlaps(cidrs, existing, exclude_asset_id=exclude_asset_id)
        if overlaps:
            raise NetworkOverlapError(overlaps)
