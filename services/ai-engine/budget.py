"""Hard daily spend cap for Claude calls.

Backed by Redis so it survives restarts and is shared across replicas. The
key auto-expires at UTC midnight, so the cap resets daily without a cron.

This is the load-bearing defense — the kill switch is a single env var that
can be unset by accident (see the May 2026 incident where ANTHROPIC_ENABLED
was set in Railway but the deployed binary predated the flag, so it was
ignored). The budget runs *unconditionally*: even with the kill switch on,
even if every other guard fails, no more than N Claude calls go out per UTC
day, full stop.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

import redis.asyncio as aioredis
import structlog

logger = structlog.get_logger(__name__)


class CallBudget:
    def __init__(self, client: aioredis.Redis, daily_limit: int):
        self._client = client
        self._daily_limit = daily_limit

    @staticmethod
    def _key(now: Optional[datetime] = None) -> str:
        d = (now or datetime.now(timezone.utc)).strftime("%Y-%m-%d")
        return f"ai_engine:budget:claude_calls:{d}"

    @staticmethod
    def _seconds_until_utc_midnight(now: Optional[datetime] = None) -> int:
        now = now or datetime.now(timezone.utc)
        tomorrow = now.replace(hour=0, minute=0, second=0, microsecond=0)
        # Next UTC midnight.
        secs = 86_400 - (now.hour * 3600 + now.minute * 60 + now.second)
        return max(secs, 60)  # never let the key live <60s — guard against clock drift

    async def try_consume(self) -> tuple[bool, int]:
        """Atomically reserve one call. Returns (allowed, current_count).

        If Redis is unreachable, FAIL CLOSED — return (False, -1). The cap
        is more important than uptime; a few minutes of stub narratives is
        cheap, a runaway loop is not.
        """
        if self._daily_limit <= 0:
            return False, 0
        key = self._key()
        try:
            count = await self._client.incr(key)
            if count == 1:
                # First call of the day — pin TTL to UTC midnight.
                await self._client.expire(key, self._seconds_until_utc_midnight())
            if count > self._daily_limit:
                return False, count
            return True, count
        except Exception as e:
            logger.error("ai_engine.budget.redis_unavailable_failing_closed", error=str(e))
            return False, -1

    async def current(self) -> int:
        try:
            raw = await self._client.get(self._key())
            return int(raw) if raw else 0
        except Exception:
            return -1

    @property
    def limit(self) -> int:
        return self._daily_limit
