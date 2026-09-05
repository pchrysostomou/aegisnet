"""SQLAlchemy implementation of :class:`aegisnet.domain.ports.AssetStore`.

Runs as the runtime role: SELECT, INSERT and UPDATE on ``assets``, plus DELETE on
``asset_networks`` (revision 0002) because a PATCH replaces an asset's networks wholesale.
Resolution is one query whose ``ORDER BY`` encodes the documented rule: most specific
CIDR, then the primary flag, then the oldest asset.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from ipaddress import ip_network
from uuid import UUID

from sqlalchemy import cast, delete, func, select, tuple_
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from aegisnet.adapters.db.models import Asset, AssetNetwork
from aegisnet.domain.assets import (
    AssetPatch,
    AssetSpec,
    HostnameConflictError,
    IPAddress,
    NetworkRecord,
    NetworkSpec,
)
from aegisnet.domain.enums import AssetEnvironment
from aegisnet.domain.pagination import decode_time_id, encode_time_id
from aegisnet.domain.ports import AssetFilter, AssetRecord, NetworkView, Page, ResolvedAsset


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _record(asset: Asset, networks: Sequence[AssetNetwork]) -> AssetRecord:
    return AssetRecord(
        id=asset.id,
        hostname=asset.hostname,
        environment=AssetEnvironment(asset.environment),
        owner=asset.owner,
        criticality=asset.criticality,
        tags=tuple(asset.tags),
        description=asset.description,
        is_active=asset.is_active,
        created_at=asset.created_at,
        updated_at=asset.updated_at,
        networks=tuple(
            NetworkView(id=n.id, cidr=ip_network(str(n.cidr)), is_primary=n.is_primary)
            for n in networks
        ),
    )


class SqlAssetStore:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._sessions = session_factory

    # ---------------------------------------------------------------- helpers
    async def _networks_for(
        self, session: AsyncSession, asset_ids: Sequence[UUID]
    ) -> dict[UUID, list[AssetNetwork]]:
        if not asset_ids:
            return {}
        rows = (
            await session.execute(
                select(AssetNetwork)
                .where(AssetNetwork.asset_id.in_(asset_ids))
                .order_by(AssetNetwork.created_at, AssetNetwork.id)
            )
        ).scalars()
        grouped: dict[UUID, list[AssetNetwork]] = {asset_id: [] for asset_id in asset_ids}
        for network in rows:
            grouped[network.asset_id].append(network)
        return grouped

    async def _load(self, session: AsyncSession, asset_id: UUID) -> AssetRecord | None:
        asset = await session.get(Asset, asset_id)
        if asset is None:
            return None
        networks = await self._networks_for(session, [asset_id])
        return _record(asset, networks[asset_id])

    @staticmethod
    def _insert(session: AsyncSession, spec: AssetSpec, now: datetime) -> Asset:
        asset = Asset(
            hostname=spec.hostname,
            environment=spec.environment,
            owner=spec.owner,
            criticality=spec.criticality,
            tags=list(spec.tags),
            description=spec.description,
            is_active=True,
            created_at=now,
            updated_at=now,
        )
        session.add(asset)
        return asset

    @staticmethod
    def _add_networks(
        session: AsyncSession, asset_id: UUID, networks: Sequence[NetworkSpec], now: datetime
    ) -> None:
        for network in networks:
            session.add(
                AssetNetwork(
                    asset_id=asset_id,
                    cidr=str(network.cidr),
                    is_primary=network.is_primary,
                    created_at=now,
                )
            )

    # ---------------------------------------------------------------- writes
    async def create(self, spec: AssetSpec, now: datetime) -> AssetRecord:
        records = await self.create_many([spec], now)
        return records[0]

    async def create_many(
        self, specs: Sequence[AssetSpec], now: datetime
    ) -> tuple[AssetRecord, ...]:
        async with self._sessions() as session:
            try:
                async with session.begin():
                    assets = [self._insert(session, spec, now) for spec in specs]
                    await session.flush()
                    for asset, spec in zip(assets, specs, strict=True):
                        self._add_networks(session, asset.id, spec.networks, now)
                    await session.flush()
                    ids = [asset.id for asset in assets]
            except IntegrityError as error:
                if "uq_assets_hostname" in str(error.orig):
                    raise HostnameConflictError("hostname already exists") from error
                raise
            networks = await self._networks_for(session, ids)
            assets_by_id = {asset.id: asset for asset in assets}
            return tuple(_record(assets_by_id[asset_id], networks[asset_id]) for asset_id in ids)

    async def update(self, asset_id: UUID, patch: AssetPatch, now: datetime) -> AssetRecord | None:
        async with self._sessions() as session:
            try:
                async with session.begin():
                    asset = await session.get(Asset, asset_id)
                    if asset is None:
                        return None
                    for field in patch.model_fields_set:
                        if field == "networks":
                            continue
                        value = getattr(patch, field)
                        setattr(asset, field, list(value) if field == "tags" else value)
                    if patch.networks is not None:
                        await session.execute(
                            delete(AssetNetwork).where(AssetNetwork.asset_id == asset_id)
                        )
                        self._add_networks(session, asset_id, patch.networks, now)
                    asset.updated_at = now
                    await session.flush()
            except IntegrityError as error:
                if "uq_assets_hostname" in str(error.orig):
                    raise HostnameConflictError("hostname already exists") from error
                raise
            return await self._load(session, asset_id)

    async def deactivate(self, asset_id: UUID, now: datetime) -> AssetRecord | None:
        async with self._sessions() as session:
            async with session.begin():
                asset = await session.get(Asset, asset_id)
                if asset is None:
                    return None
                asset.is_active = False
                asset.updated_at = now
            return await self._load(session, asset_id)

    # ---------------------------------------------------------------- reads
    async def get(self, asset_id: UUID) -> AssetRecord | None:
        async with self._sessions() as session:
            return await self._load(session, asset_id)

    async def get_by_hostname(self, hostname: str) -> AssetRecord | None:
        async with self._sessions() as session:
            asset = (
                await session.execute(select(Asset).where(Asset.hostname == hostname))
            ).scalar_one_or_none()
            if asset is None:
                return None
            networks = await self._networks_for(session, [asset.id])
            return _record(asset, networks[asset.id])

    async def list(self, query: AssetFilter) -> Page[AssetRecord]:
        statement = select(Asset)
        if not query.include_inactive:
            statement = statement.where(Asset.is_active.is_(True))
        if query.environment is not None:
            statement = statement.where(Asset.environment == query.environment)
        if query.criticality_min is not None:
            statement = statement.where(Asset.criticality >= query.criticality_min)
        if query.tag is not None:
            statement = statement.where(Asset.tags.contains([query.tag]))
        if query.q:
            statement = statement.where(
                Asset.hostname.ilike(f"%{_escape_like(query.q)}%", escape="\\")
            )
        if query.cursor is not None:
            moment, last_id = decode_time_id(query.cursor)
            statement = statement.where(tuple_(Asset.created_at, Asset.id) < (moment, last_id))
        statement = statement.order_by(Asset.created_at.desc(), Asset.id.desc()).limit(
            query.limit + 1
        )
        async with self._sessions() as session:
            assets = list((await session.execute(statement)).scalars())
            has_more = len(assets) > query.limit
            assets = assets[: query.limit]
            networks = await self._networks_for(session, [asset.id for asset in assets])
        items = tuple(_record(asset, networks[asset.id]) for asset in assets)
        next_cursor = (
            encode_time_id(assets[-1].created_at, assets[-1].id) if has_more and assets else None
        )
        return Page(items=items, next_cursor=next_cursor)

    async def networks(self, *, active_only: bool = True) -> tuple[NetworkRecord, ...]:
        statement = select(AssetNetwork, Asset.created_at).join(
            Asset, Asset.id == AssetNetwork.asset_id
        )
        if active_only:
            statement = statement.where(Asset.is_active.is_(True))
        async with self._sessions() as session:
            rows = (await session.execute(statement)).all()
        return tuple(
            NetworkRecord(
                asset_id=network.asset_id,
                cidr=ip_network(str(network.cidr)),
                is_primary=network.is_primary,
                asset_created_at=created_at,
            )
            for network, created_at in rows
        )

    async def resolve(self, address: IPAddress) -> ResolvedAsset | None:
        """``cidr >>= address``, best match first: longest prefix, primary, oldest asset."""
        probe = cast(str(address), INET)
        statement = (
            select(AssetNetwork)
            .join(Asset, Asset.id == AssetNetwork.asset_id)
            .where(Asset.is_active.is_(True), AssetNetwork.cidr.op(">>=")(probe))
            .order_by(
                func.masklen(AssetNetwork.cidr).desc(),
                AssetNetwork.is_primary.desc(),
                Asset.created_at.asc(),
                Asset.id.asc(),
            )
            .limit(1)
        )
        async with self._sessions() as session:
            network = (await session.execute(statement)).scalar_one_or_none()
            if network is None:
                return None
            record = await self._load(session, network.asset_id)
        if record is None:  # pragma: no cover - the join proved it exists
            return None
        return ResolvedAsset(asset=record, matched_cidr=ip_network(str(network.cidr)))
