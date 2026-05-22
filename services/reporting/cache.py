"""Tiny per-tenant Redis JSON cache.

5-minute TTL so the executive dashboard can refresh without hammering the
upstream services. Falls back to no-op if Redis is unreachable so the
service still responds with fresh data on cache failure.
"""

from __future__ import annotations

import json
from typing import Any, Optional

import structlog

logger = structlog.get_logger(__name__)


class TenantCache:
    def __init__(self, redis_client: Any, ttl_seconds: int = 300) -> None:
        self.redis = redis_client
        self.ttl = ttl_seconds

    @staticmethod
    def key(tenant_id: str, scope: str) -> str:
        return f"reporting:{tenant_id}:{scope}"

    async def get(self, tenant_id: str, scope: str) -> Optional[dict[str, Any]]:
        if self.redis is None:
            return None
        try:
            raw = await self.redis.get(self.key(tenant_id, scope))
            if raw is None:
                return None
            text = raw.decode() if isinstance(raw, (bytes, bytearray)) else str(raw)
            return json.loads(text)
        except Exception as e:
            logger.warning("reporting.cache.get_failed", error=str(e))
            return None

    async def set(self, tenant_id: str, scope: str, value: dict[str, Any]) -> None:
        if self.redis is None:
            return
        try:
            await self.redis.setex(
                self.key(tenant_id, scope), self.ttl, json.dumps(value, default=str)
            )
        except Exception as e:
            logger.warning("reporting.cache.set_failed", error=str(e))
