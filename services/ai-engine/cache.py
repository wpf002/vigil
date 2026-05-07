"""Redis-backed narrative cache.

Key format: narrative:{attack_id}:{confidence_2dp}
- Skip the API call if the same (attack_id, confidence) was generated recently.
- TTL bounds staleness; eviction handled by Redis.
"""

from __future__ import annotations
import json
from typing import Optional

import redis.asyncio as aioredis
import structlog

logger = structlog.get_logger(__name__)


class NarrativeCache:
    def __init__(self, client: aioredis.Redis, ttl_seconds: int):
        self._client = client
        self._ttl = ttl_seconds

    @classmethod
    async def from_url(cls, url: str, ttl_seconds: int) -> "NarrativeCache":
        client = aioredis.from_url(url, encoding="utf-8", decode_responses=True)
        return cls(client, ttl_seconds)

    async def close(self) -> None:
        try:
            await self._client.aclose()
        except Exception:
            pass

    @staticmethod
    def _key(attack_id: str, confidence: float) -> str:
        return f"narrative:{attack_id}:{round(confidence, 2):.2f}"

    async def get(self, attack_id: str, confidence: float) -> Optional[dict]:
        try:
            raw = await self._client.get(self._key(attack_id, confidence))
        except Exception as e:
            logger.warning("narrative_cache.get_failed", error=str(e))
            return None
        if raw is None:
            return None
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return None

    async def set(self, attack_id: str, confidence: float, payload: dict) -> None:
        try:
            await self._client.set(
                self._key(attack_id, confidence),
                json.dumps(payload),
                ex=self._ttl,
            )
        except Exception as e:
            logger.warning("narrative_cache.set_failed", error=str(e))

    async def latest_confidence(self, attack_id: str) -> Optional[float]:
        """Return the most-recent cached confidence for this attack, if any.

        Used to apply the 'delta < 0.05 → skip' rule. Scans the keyspace
        for keys matching the attack_id prefix; if multiple TTLs are alive
        we take the largest (most recent) confidence.
        """
        try:
            keys = []
            async for k in self._client.scan_iter(match=f"narrative:{attack_id}:*", count=100):
                keys.append(k)
        except Exception as e:
            logger.warning("narrative_cache.scan_failed", error=str(e))
            return None
        if not keys:
            return None
        confidences: list[float] = []
        for k in keys:
            try:
                _, _, c = k.split(":")
                confidences.append(float(c))
            except (ValueError, AttributeError):
                continue
        return max(confidences) if confidences else None
