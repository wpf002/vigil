"""Daily snapshot scheduler.

Runs once per day at 00:05 UTC (configurable). For each known tenant
it computes the executive summary and persists a row in
metric_snapshots. Sleeping until the next scheduled run is calculated
exactly so a missed wake-up still picks up on the next cycle.
"""

from __future__ import annotations
import asyncio
import json
from datetime import datetime, time, timedelta, timezone
from typing import Any, Optional
from uuid import UUID

import asyncpg
import structlog

from .aggregator import Aggregator

logger = structlog.get_logger(__name__)


class SnapshotScheduler:
    def __init__(
        self,
        *,
        pool: asyncpg.Pool,
        aggregator: Aggregator,
        hour_utc: int,
        minute_utc: int,
    ):
        self.pool = pool
        self.aggregator = aggregator
        self.hour_utc = hour_utc
        self.minute_utc = minute_utc
        self._task: Optional[asyncio.Task] = None
        self._stop = asyncio.Event()

    def start(self) -> None:
        if self._task is None:
            self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        self._stop.set()
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass

    async def _run(self) -> None:
        while not self._stop.is_set():
            now = datetime.now(timezone.utc)
            next_fire = _next_fire(now, self.hour_utc, self.minute_utc)
            seconds = (next_fire - now).total_seconds()
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=seconds)
                return
            except asyncio.TimeoutError:
                pass
            try:
                await self.run_once()
            except Exception as e:  # pragma: no cover — defensive
                logger.exception("reporting.scheduler.run_failed", error=str(e))

    async def run_once(self) -> int:
        """Compute and persist a daily snapshot for every distinct tenant
        we can find in the metric_snapshots history. Returns count written."""
        tenants = await self._distinct_tenants()
        written = 0
        for tid in tenants:
            try:
                metrics = await self.aggregator.executive_summary(tid)
                await self.persist(
                    tenant_id=tid,
                    snapshot_type="daily",
                    metrics=metrics,
                )
                written += 1
            except Exception as e:
                logger.warning("reporting.snapshot.failed", tenant_id=str(tid), error=str(e))
        logger.info("reporting.snapshot.complete", written=written, tenants=len(tenants))
        return written

    async def _distinct_tenants(self) -> list[UUID]:
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT DISTINCT tenant_id FROM metric_snapshots"
            )
        return [r["tenant_id"] for r in rows]

    async def persist(
        self,
        *,
        tenant_id: UUID,
        snapshot_type: str,
        metrics: dict[str, Any],
        period_start: Optional[datetime] = None,
        period_end: Optional[datetime] = None,
    ) -> UUID:
        end = period_end or datetime.now(timezone.utc).replace(microsecond=0)
        if snapshot_type == "weekly":
            start = period_start or (end - timedelta(days=7))
        elif snapshot_type == "monthly":
            start = period_start or (end - timedelta(days=30))
        else:
            start = period_start or (end - timedelta(days=1))

        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO metric_snapshots (
                    tenant_id, snapshot_type, period_start, period_end, metrics
                ) VALUES ($1, $2, $3, $4, $5::jsonb)
                RETURNING snapshot_id
                """,
                tenant_id,
                snapshot_type,
                start,
                end,
                json.dumps(metrics, default=str),
            )
        return row["snapshot_id"]


def _next_fire(now: datetime, hour: int, minute: int) -> datetime:
    today_fire = datetime.combine(now.date(), time(hour, minute), tzinfo=timezone.utc)
    if now < today_fire:
        return today_fire
    return today_fire + timedelta(days=1)
