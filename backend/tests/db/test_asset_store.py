"""The SQL asset store against PostgreSQL 16: networks, filters, pagination, resolution."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address, ip_network
from uuid import uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from aegisnet.adapters.db.asset_store import SqlAssetStore
from aegisnet.adapters.db.session import make_session_factory
from aegisnet.domain.assets import AssetPatch, AssetSpec, HostnameConflictError, NetworkOverlapError
from aegisnet.domain.enums import AssetEnvironment
from aegisnet.domain.ports import AssetFilter
from aegisnet.services.asset_service import AssetService
from tests.conftest import REPO_ROOT

pytestmark = [pytest.mark.db, pytest.mark.integration]

T0 = datetime(2026, 9, 5, 12, 0, tzinfo=UTC)


@pytest.fixture(autouse=True)
async def clean_assets(migrator_engine: AsyncEngine) -> AsyncIterator[None]:
    async with migrator_engine.begin() as connection:
        await connection.execute(text("DELETE FROM asset_networks"))
        await connection.execute(text("DELETE FROM assets"))
    yield


@pytest.fixture
def store(app_engine: AsyncEngine) -> SqlAssetStore:
    return SqlAssetStore(make_session_factory(app_engine))


@pytest.fixture
def service(store: SqlAssetStore) -> AssetService:
    clock = iter(T0 + timedelta(seconds=i) for i in range(10_000))
    return AssetService(store, clock=lambda: next(clock))


def _spec(hostname: str, *cidrs: str, **extra: object) -> AssetSpec:
    return AssetSpec.model_validate(
        {
            "hostname": hostname,
            "environment": "lab",
            "networks": [{"cidr": cidr, "is_primary": i == 0} for i, cidr in enumerate(cidrs)],
            **extra,
        }
    )


async def test_create_get_and_hostname_lookup(service: AssetService, store: SqlAssetStore) -> None:
    created = await service.create(
        _spec("ws-10.lab.example.test", "10.10.0.10/32", tags=["workstation"], criticality=2)
    )
    fetched = await store.get(created.id)
    assert fetched == created
    assert fetched.environment is AssetEnvironment.lab
    assert fetched.tags == ("workstation",)
    assert [str(n.cidr) for n in fetched.networks] == ["10.10.0.10/32"]
    assert (await store.get_by_hostname("ws-10.lab.example.test")) == created
    assert await store.get(uuid4()) is None


async def test_hostname_uniqueness_is_enforced_by_the_database_too(store: SqlAssetStore) -> None:
    await store.create(_spec("same.lab.example.test"), T0)
    with pytest.raises(HostnameConflictError):
        await store.create(_spec("same.lab.example.test"), T0)


async def test_create_many_is_atomic(store: SqlAssetStore) -> None:
    await store.create(_spec("taken.lab.example.test"), T0)
    with pytest.raises(HostnameConflictError):
        await store.create_many(
            [_spec("fresh.lab.example.test", "10.1.0.0/24"), _spec("taken.lab.example.test")], T0
        )
    assert await store.get_by_hostname("fresh.lab.example.test") is None
    assert await store.networks() == ()


async def test_update_replaces_networks_using_the_delete_grant(service: AssetService) -> None:
    record = await service.create(_spec("edit.lab.example.test", "10.2.0.0/24", "10.2.0.9/32"))
    patch = AssetPatch.model_validate(
        {"owner": "blue-team", "tags": ["core", "edited"], "networks": [{"cidr": "10.3.0.0/24"}]}
    )
    updated = await service.update(record.id, patch)
    assert updated.owner == "blue-team" and updated.tags == ("core", "edited")
    assert [str(n.cidr) for n in updated.networks] == ["10.3.0.0/24"]
    assert updated.updated_at > record.updated_at
    assert await service.resolve(ip_address("10.2.0.9")) is None


async def test_list_filters_and_keyset_pagination(service: AssetService) -> None:
    for index in range(7):
        await service.create(
            _spec(
                f"host-{index}.lab.example.test",
                f"10.9.{index}.0/24",
                criticality=(index % 5) + 1,
                tags=["even"] if index % 2 == 0 else ["odd"],
                environment="staging" if index == 6 else "lab",
            )
        )
    await service.deactivate((await service.list(AssetFilter(q="host-3"))).items[0].id)

    first = await service.list(AssetFilter(limit=3))
    assert [a.hostname for a in first.items] == [f"host-{i}.lab.example.test" for i in (6, 5, 4)]
    assert first.next_cursor is not None
    second = await service.list(AssetFilter(limit=3, cursor=first.next_cursor))
    assert [a.hostname for a in second.items] == [f"host-{i}.lab.example.test" for i in (2, 1, 0)]
    assert second.next_cursor is None  # host-3 is inactive and hidden

    assert len((await service.list(AssetFilter(include_inactive=True, limit=200))).items) == 7
    assert [
        a.hostname
        for a in (await service.list(AssetFilter(environment=AssetEnvironment.staging))).items
    ] == ["host-6.lab.example.test"]
    assert {a.criticality for a in (await service.list(AssetFilter(criticality_min=4))).items} <= {
        4,
        5,
    }
    assert all("even" in a.tags for a in (await service.list(AssetFilter(tag="even"))).items)
    assert [a.hostname for a in (await service.list(AssetFilter(q="HOST-5"))).items] == [
        "host-5.lab.example.test"
    ]
    assert (await service.list(AssetFilter(q="%"))).items == ()


async def test_resolution_order_most_specific_primary_then_oldest(
    store: SqlAssetStore, migrator_engine: AsyncEngine
) -> None:
    """The service refuses cross-asset overlaps, so the owner inserts them directly to prove
    the query's ORDER BY implements the documented precedence."""
    older = await store.create(_spec("older.lab.example.test"), T0)
    newer = await store.create(_spec("newer.lab.example.test"), T0 + timedelta(hours=1))
    host = await store.create(_spec("host.lab.example.test"), T0 + timedelta(hours=2))
    async with migrator_engine.begin() as connection:
        for asset_id, cidr, primary in (
            (older.id, "10.7.0.0/24", False),
            (newer.id, "10.7.0.0/24", True),
            (host.id, "10.7.0.42/32", False),
        ):
            await connection.execute(
                text(
                    "INSERT INTO asset_networks (asset_id, cidr, is_primary, created_at) "
                    "VALUES (:a, CAST(:c AS cidr), :p, now())"
                ),
                {"a": asset_id, "c": cidr, "p": primary},
            )
    hit = await store.resolve(ip_address("10.7.0.42"))
    assert hit is not None and hit.asset.id == host.id and str(hit.matched_cidr) == "10.7.0.42/32"
    hit = await store.resolve(ip_address("10.7.0.5"))
    assert hit is not None and hit.asset.id == newer.id  # primary beats older on a tie
    async with migrator_engine.begin() as connection:
        await connection.execute(
            text("UPDATE asset_networks SET is_primary = false WHERE asset_id = :a"),
            {"a": newer.id},
        )
    hit = await store.resolve(ip_address("10.7.0.5"))
    assert hit is not None and hit.asset.id == older.id  # then the oldest asset
    assert await store.resolve(ip_address("192.0.2.1")) is None


async def test_networks_lists_active_assets_only_by_default(
    service: AssetService, store: SqlAssetStore
) -> None:
    kept = await service.create(_spec("kept.lab.example.test", "10.11.0.0/24"))
    dropped = await service.create(_spec("dropped.lab.example.test", "10.12.0.0/24"))
    await service.deactivate(dropped.id)
    assert {n.asset_id for n in await store.networks()} == {kept.id}
    assert {n.asset_id for n in await store.networks(active_only=False)} == {kept.id, dropped.id}
    assert next(iter(await store.networks())).cidr == ip_network("10.11.0.0/24")


async def test_the_committed_seed_file_seeds_idempotently(service: AssetService) -> None:
    from aegisnet.cli import load_seed_file

    specs = load_seed_file(REPO_ROOT / "samples", "lab-assets")
    first = await service.seed(specs)
    assert (first.created, first.updated) == (14, 0)
    again = await service.seed(specs)
    assert (again.created, again.updated) == (0, 14)
    resolved = await service.resolve(ip_address("10.10.0.53"))
    assert resolved is not None and resolved.asset.hostname == "resolver.lab.example.test"
    with pytest.raises(NetworkOverlapError):
        await service.create(_spec("intruder.lab.example.test", "10.10.0.0/24"))
