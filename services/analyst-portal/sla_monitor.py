"""Background SLA breach monitor.

Every interval: scan escalation_queue for unresolved entries past their
sla_deadline, mark them breached, log at WARNING. Notifications (email,
Slack, etc.) are stubbed.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Optional

import structlog

from .store import AnalystPortalStore

logger = structlog.get_logger(__name__)


async def notify_breach(queue_entry: dict) -> None:
    """Stub for downstream notifications. TODO: wire up email/Slack/PagerDuty."""
    logger.warning(
        "analyst_portal.sla.breached",
        queue_id=str(queue_entry["queue_id"]),
        attack_id=str(queue_entry["attack_id"]),
        tenant_id=str(queue_entry["tenant_id"]),
        priority=queue_entry["priority"],
        deadline=queue_entry["sla_deadline"].isoformat(),
    )


async def sweep_once(store: AnalystPortalStore, now: Optional[datetime] = None) -> int:
    now = now or datetime.now(timezone.utc)
    breached = await store.find_breaches(now=now)
    for entry in breached:
        await store.mark_breached(entry["queue_id"])
        await notify_breach(entry)
    return len(breached)


class SLAMonitor:
    def __init__(self, store: AnalystPortalStore, interval_seconds: int):
        self.store = store
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
        while not self._stop.is_set():
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self.interval_seconds)
                return
            except asyncio.TimeoutError:
                pass
            try:
                breached = await sweep_once(self.store)
                if breached:
                    logger.info("analyst_portal.sla.swept", breached=breached)
            except Exception as e:
                logger.warning("analyst_portal.sla.sweep_failed", error=str(e))
