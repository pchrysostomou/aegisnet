"""Asset use-cases against an in-memory store: conflicts, overlaps, seeding, updates."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address, ip_network
from uuid import UUID, uuid4

import pytest

from aegisnet.domain.assets import (
    AssetNotFoundError,
    AssetPatch,
    AssetSpec,
    BulkTooLargeError,
    HostnameConflictError,
    IPAddress,
    NetworkOverlapError,
    NetworkRecord,
    resolve_ip,
)
from aegisnet.domain.enums import AssetEnvironment
from aegisnet.domain.pagination import InvalidCursorError, encode_time_id
from aegisnet.domain.ports import AssetFilter, AssetRecord, NetworkView, Page, ResolvedAsset
from aegisnet.services.asset_service import AssetService

pytestmark = pytest.mark.unit

T0 = datetime(2026, 9, 1, tzinfo=UTC)


class FakeAssetStore:
    def __init__(self) -> None:
        self.rows: dict[UUID, AssetRecord] = {}
        self.create_many_calls = 0

    def _build(self, spec: AssetSpec, now: datetime, asset_id: UUID | None = None) -> AssetRecord:
        return AssetRecord(
            id=asset_id or uuid4(),
            hostname=spec.hostname,
            environment=spec.environment,
            owner=spec.owner,
            criticality=spec.criticality,
            tags=tuple(spec.tags),
            description=spec.description,
            is_active=True,
            created_at=now,
            updated_at=now,
            networks=tuple(NetworkView(uuid4(), n.cidr, n.is_primary) for n in spec.networks),
        )

    async def create(self, spec: AssetSpec, now: datetime) -> AssetRecord:
        record = self._build(spec, now)
        self.rows[record.id] = record
        return record

    async def create_many(
        self, specs: Sequence[AssetSpec], now: datetime
    ) -> tuple[AssetRecord, ...]:
        self.create_many_calls += 1
        created = tuple(self._build(spec, now) for spec in specs)
        for record in created:
            self.rows[record.id] = record
        return created

    async def get(self, asset_id: UUID) -> AssetRecord | None:
        return self.rows.get(asset_id)

    async def get_by_hostname(self, hostname: str) -> AssetRecord | None:
        return next((r for r in self.rows.values() if r.hostname == hostname), None)

    async def list(self, query: AssetFilter) -> Page[AssetRecord]:
        rows = [r for r in self.rows.values() if query.include_inactive or r.is_active]
        return Page(items=tuple(rows[: query.limit]), next_cursor=None)

    async def update(self, asset_id: UUID, patch: AssetPatch, now: datetime) -> AssetRecord | None:
        current = self.rows.get(asset_id)
        if current is None:
            return None
        values = {field: getattr(current, field) for field in current.__dataclass_fields__}
        for field in patch.model_fields_set:
            if field == "networks":
                assert patch.networks is not None
                values["networks"] = tuple(
                    NetworkView(uuid4(), n.cidr, n.is_primary) for n in patch.networks
                )
            elif field == "tags":
                values["tags"] = tuple(patch.tags or ())
            else:
                values[field] = getattr(patch, field)
        values["updated_at"] = now
        self.rows[asset_id] = AssetRecord(**values)
        return self.rows[asset_id]

    async def deactivate(self, asset_id: UUID, now: datetime) -> AssetRecord | None:
        return await self.update(asset_id, AssetPatch(is_active=False), now)

    async def networks(self, *, active_only: bool = True) -> tuple[NetworkRecord, ...]:
        return tuple(
            NetworkRecord(r.id, n.cidr, n.is_primary, r.created_at)
            for r in self.rows.values()
            if r.is_active or not active_only
            for n in r.networks
        )

    async def resolve(self, address: IPAddress) -> ResolvedAsset | None:
        hit = resolve_ip(address, await self.networks())
        return None if hit is None else ResolvedAsset(self.rows[hit.asset_id], hit.cidr)


def _spec(hostname: str, *cidrs: str, **extra: object) -> AssetSpec:
    return AssetSpec.model_validate(
        {
            "hostname": hostname,
            "environment": "lab",
            "networks": [{"cidr": cidr, "is_primary": i == 0} for i, cidr in enumerate(cidrs)],
            **extra,
        }
    )


@pytest.fixture
def store() -> FakeAssetStore:
    return FakeAssetStore()


@pytest.fixture
def service(store: FakeAssetStore) -> AssetService:
    clock = iter(T0 + timedelta(minutes=i) for i in range(1000))
    return AssetService(store, clock=lambda: next(clock))


async def test_create_stores_networks_and_stamps_the_clock(service: AssetService) -> None:
    record = await service.create(_spec("ws-10.example.test", "10.10.0.10/32"))
    assert record.hostname == "ws-10.example.test"
    assert [str(n.cidr) for n in record.networks] == ["10.10.0.10/32"]
    assert record.networks[0].is_primary is True
    assert record.created_at == T0


async def test_duplicate_hostname_is_refused(service: AssetService) -> None:
    await service.create(_spec("dup.example.test"))
    with pytest.raises(HostnameConflictError):
        await service.create(_spec("DUP.example.test"))


async def test_cross_asset_overlap_is_refused_and_named(service: AssetService) -> None:
    await service.create(_spec("a.example.test", "10.10.0.0/24"))
    with pytest.raises(NetworkOverlapError) as excinfo:
        await service.create(_spec("b.example.test", "10.10.0.11/32"))
    assert "10.10.0.11/32 overlaps 10.10.0.0/24" in str(excinfo.value)
    assert excinfo.value.overlaps[0].other_cidr == ip_network("10.10.0.0/24")


async def test_an_asset_may_hold_nested_networks_of_its_own(service: AssetService) -> None:
    record = await service.create(_spec("site.example.test", "10.20.0.0/24", "10.20.0.7/32"))
    resolved = await service.resolve(ip_address("10.20.0.7"))
    assert resolved is not None
    assert resolved.asset.id == record.id and str(resolved.matched_cidr) == "10.20.0.7/32"


async def test_update_replaces_networks_and_ignores_its_own_old_ones(
    service: AssetService, store: FakeAssetStore
) -> None:
    record = await service.create(_spec("x.example.test", "10.30.0.0/24"))
    patch = AssetPatch.model_validate(
        {"criticality": 5, "networks": [{"cidr": "10.30.0.0/25", "is_primary": True}]}
    )
    updated = await service.update(record.id, patch)
    assert updated.criticality == 5
    assert [str(n.cidr) for n in updated.networks] == ["10.30.0.0/25"]
    assert updated.updated_at > record.updated_at
    other = await service.create(_spec("y.example.test", "10.30.0.128/25"))
    with pytest.raises(NetworkOverlapError):
        await service.update(
            other.id, AssetPatch.model_validate({"networks": [{"cidr": "10.30.0.0/25"}]})
        )


async def test_update_rejects_a_taken_hostname_but_allows_keeping_ones_own(
    service: AssetService,
) -> None:
    first = await service.create(_spec("one.example.test"))
    await service.create(_spec("two.example.test"))
    await service.update(first.id, AssetPatch.model_validate({"hostname": "one.example.test"}))
    with pytest.raises(HostnameConflictError):
        await service.update(first.id, AssetPatch.model_validate({"hostname": "two.example.test"}))


async def test_deactivate_hides_from_resolution_and_frees_its_networks(
    service: AssetService,
) -> None:
    record = await service.create(_spec("gone.example.test", "10.40.0.0/24"))
    deactivated = await service.deactivate(record.id)
    assert deactivated.is_active is False
    assert await service.resolve(ip_address("10.40.0.1")) is None
    await service.create(_spec("new.example.test", "10.40.0.0/24"))  # no overlap with inactive


async def test_unknown_assets_raise(service: AssetService) -> None:
    with pytest.raises(AssetNotFoundError):
        await service.get(uuid4())
    with pytest.raises(AssetNotFoundError):
        await service.update(uuid4(), AssetPatch(criticality=1))
    with pytest.raises(AssetNotFoundError):
        await service.deactivate(uuid4())


async def test_bulk_create_checks_everything_before_writing(
    service: AssetService, store: FakeAssetStore
) -> None:
    await service.create(_spec("taken.example.test", "10.50.0.0/24"))
    with pytest.raises(HostnameConflictError, match="duplicate hostname in request"):
        await service.bulk_create([_spec("d.example.test"), _spec("d.example.test")])
    with pytest.raises(NetworkOverlapError):
        await service.bulk_create(
            [_spec("m.example.test", "10.60.0.0/24"), _spec("n.example.test", "10.60.0.9/32")]
        )
    with pytest.raises(NetworkOverlapError):
        await service.bulk_create([_spec("o.example.test", "10.50.0.1/32")])
    with pytest.raises(HostnameConflictError, match="already exists"):
        await service.bulk_create([_spec("taken.example.test")])
    with pytest.raises(BulkTooLargeError):
        await service.bulk_create([_spec(f"h{i}.example.test") for i in range(501)])
    assert store.create_many_calls == 0
    created = await service.bulk_create(
        [_spec("p.example.test", "10.70.0.0/24"), _spec("q.example.test")]
    )
    assert len(created) == 2 and store.create_many_calls == 1


async def test_seed_creates_then_updates_by_hostname(
    service: AssetService, store: FakeAssetStore
) -> None:
    specs = [
        _spec("a.example.test", "10.80.0.1/32", criticality=2),
        _spec("b.example.test", "10.80.0.2/32"),
    ]
    first = await service.seed(specs)
    assert (first.created, first.updated) == (2, 0)
    again = await service.seed(
        [_spec("a.example.test", "10.80.0.9/32", criticality=5), _spec("c.example.test")]
    )
    assert (again.created, again.updated) == (1, 1)
    a = await service.get((await store.get_by_hostname("a.example.test")).id)  # type: ignore[union-attr]
    assert a.criticality == 5 and [str(n.cidr) for n in a.networks] == ["10.80.0.9/32"]
    assert len(store.rows) == 3
    with pytest.raises(HostnameConflictError, match="needs a hostname"):
        await service.seed([AssetSpec.model_validate({"environment": "lab"})])


async def test_list_validates_limit_and_cursor(service: AssetService) -> None:
    with pytest.raises(ValueError, match="between 1 and"):
        await service.list(AssetFilter(limit=201))
    with pytest.raises(InvalidCursorError):
        await service.list(AssetFilter(cursor="junk"))
    page = await service.list(AssetFilter(cursor=encode_time_id(T0, uuid4())))
    assert page.items == ()


def test_environment_round_trip_on_records() -> None:
    assert _spec("z.example.test", environment="staging").environment is AssetEnvironment.staging
