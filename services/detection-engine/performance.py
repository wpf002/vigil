"""Background performance aggregation.

Every interval, sweeps all active detection_versions and computes 7d / 30d
detection_performance rollups from detection_signals. fp_rate is guarded
against zero division — a detection that hasn't fired produces fp_rate=None.

Runs as a single asyncio task launched from the FastAPI lifespan.
"""

from __future__ import annotations
import asyncio
from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import UUID

import structlog

from .store import DetectionStore

logger = structlog.get_logger(__name__)


def compute_fp_rate(false_positives: int, total_fires: int) -> Optional[float]:
    """fp_rate = false_positives / total_fires, or None when zero fires.

    Guards against ZeroDivisionError. Centralised so the test can target it
    independently of the asyncpg call path.
    """
    if total_fires <= 0:
        return None
    return false_positives / total_fires


async def aggregate_for_detection(
    *,
    store: DetectionStore,
    detection_id: str,
    tenant_id: UUID,
    window_days: int,
    now: Optional[datetime] = None,
) -> dict:
    """Compute and persist a single window. Returns the rollup dict written."""
    now = now or datetime.now(timezone.utc)
    period_end = now
    period_start = now - timedelta(days=window_days)

    agg = await store.aggregate_window(detection_id, tenant_id, period_start, period_end)
    total_fires = int(agg.get("total_fires") or 0)
    false_positives = int(agg.get("false_positives") or 0)
    true_positives = int(agg.get("true_positives") or 0)
    escalations = int(agg.get("escalations") or 0)
    avg_confidence = agg.get("avg_confidence")
    if avg_confidence is not None:
        avg_confidence = float(avg_confidence)

    fp_rate = compute_fp_rate(false_positives, total_fires)

    rollup = {
        "detection_id": detection_id,
        "tenant_id": str(tenant_id),
        "period_start": period_start,
        "period_end": period_end,
        "total_fires": total_fires,
        "false_positives": false_positives,
        "true_positives": true_positives,
        "escalations": escalations,
        "fp_rate": fp_rate,
        "avg_confidence": avg_confidence,
    }

    await store.upsert_performance(
        detection_id=detection_id,
        tenant_id=tenant_id,
        period_start=period_start,
        period_end=period_end,
        total_fires=total_fires,
        false_positives=false_positives,
        true_positives=true_positives,
        escalations=escalations,
        fp_rate=fp_rate,
        avg_confidence=avg_confidence,
    )
    return rollup


async def aggregate_all(
    *,
    store: DetectionStore,
    tenant_id: UUID,
    now: Optional[datetime] = None,
) -> int:
    """Run aggregation for every active detection in this tenant.

    Returns the number of (detection × window) rollups written.
    """
    detections = await store.list_active_detections(tenant_id)
    written = 0
    for det in detections:
        for window in (7, 30):
            try:
                await aggregate_for_detection(
                    store=store,
                    detection_id=det["detection_id"],
                    tenant_id=tenant_id,
                    window_days=window,
                    now=now,
                )
                written += 1
            except Exception as e:
                logger.warning(
                    "performance.aggregate_failed",
                    detection_id=det["detection_id"],
                    window_days=window,
                    error=str(e),
                )
    return written


class PerformanceAggregator:
    """Long-running asyncio task that aggregates on a fixed interval."""

    def __init__(
        self,
        store: DetectionStore,
        tenant_id: UUID,
        interval_seconds: int,
    ):
        self.store = store
        self.tenant_id = tenant_id
        self.interval_seconds = interval_seconds
        self._task: Optional[asyncio.Task] = None
        self._stop = asyncio.Event()

    def start(self) -> None:
        if self._task is None or self._task.done():
            self._stop.clear()
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
        # Run once immediately so /coverage and /performance return data fast.
        try:
            await aggregate_all(store=self.store, tenant_id=self.tenant_id)
        except Exception as e:
            logger.warning("performance.initial_run_failed", error=str(e))

        while not self._stop.is_set():
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self.interval_seconds)
                # _stop set — exit.
                return
            except asyncio.TimeoutError:
                pass
            try:
                count = await aggregate_all(store=self.store, tenant_id=self.tenant_id)
                logger.info("performance.aggregated", rollups=count)
            except Exception as e:
                logger.warning("performance.tick_failed", error=str(e))
