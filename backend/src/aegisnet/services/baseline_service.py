"""The baseline recompute job (Milestone 2, Chunk 11; ADR-019).

For every active asset, the hourly outbound bytes of the last ``window_days`` are summarised
into ``asset_baselines`` (mean, population standard deviation, nearest-rank p95, the number
of hours that had any outbound flow). D-005 reads those rows through the sweep; nothing here
runs inside a detector, which is what keeps the rules deterministic.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

from aegisnet.domain.assets import IPNetwork
from aegisnet.domain.detectors import summarize
from aegisnet.domain.enums import BaselineMetric
from aegisnet.domain.ports import AssetStore, BaselineRecord, BaselineStore, OutboundHistoryStore
from aegisnet.logging import get_logger

logger = get_logger(__name__)

MAX_WINDOW_DAYS = 90


class BaselineError(ValueError):
    pass


def utc_now() -> datetime:
    return datetime.now(tz=UTC)


@dataclass(frozen=True, slots=True)
class BaselineRun:
    window_days: int
    window_start: datetime
    window_end: datetime
    assets_considered: int
    baselines_written: int
    computed_at: datetime


class BaselineService:
    def __init__(
        self,
        assets: AssetStore,
        history: OutboundHistoryStore,
        baselines: BaselineStore,
        *,
        clock: Callable[[], datetime] = utc_now,
        window_days: int = 7,
    ) -> None:
        if not 1 <= window_days <= MAX_WINDOW_DAYS:
            raise BaselineError(f"window_days must be between 1 and {MAX_WINDOW_DAYS}")
        self._assets = assets
        self._history = history
        self._baselines = baselines
        self._clock = clock
        self._window_days = window_days

    async def recompute(self, *, until: datetime | None = None) -> BaselineRun:
        """Summarise the complete hours before ``until`` (the current hour is excluded, it is
        still being written) over ``window_days`` days, one row per asset that had any
        outbound flow. Assets with no outbound history get no row: D-005 abstains for them."""
        now = self._clock()
        end = (until or now).astimezone(UTC).replace(minute=0, second=0, microsecond=0)
        start = end - timedelta(days=self._window_days)
        by_asset: dict[UUID, list[IPNetwork]] = defaultdict(list)
        for network in await self._assets.networks(active_only=True):
            by_asset[network.asset_id].append(network.cidr)
        written = 0
        for asset_id in sorted(by_asset, key=lambda a: a.int):
            hours = await self._history.hourly_outbound_bytes(by_asset[asset_id], start, end)
            if not hours:
                continue
            summary = summarize([total for _, total in hours])
            await self._baselines.upsert(
                asset_id=asset_id,
                metric=BaselineMetric.outbound_bytes_per_hour,
                window_days=self._window_days,
                mean=summary.mean,
                stddev=summary.stddev,
                p95=summary.p95,
                sample_count=summary.sample_count,
                now=now,
            )
            written += 1
        logger.info(
            "baselines_recomputed",
            extra={"assets": len(by_asset), "written": written, "window_days": self._window_days},
        )
        return BaselineRun(self._window_days, start, end, len(by_asset), written, now)

    async def list(self) -> tuple[BaselineRecord, ...]:
        return await self._baselines.list()
