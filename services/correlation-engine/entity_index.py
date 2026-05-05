"""
Redis-backed entity → attack_id index, idempotency tracker, and distributed lock.

Keys (all prefixed by tenant_id for isolation):
    vigil:entity:{tenant}:{entity_type}:{entity_value}      → attack_id    (TTL)
    vigil:processed:{tenant}:{event_id}                     → '1'          (TTL)
    vigil:lock:{tenant}:{lock_key}                          → token        (TTL, NX)
"""

from __future__ import annotations
import asyncio
import secrets
from contextlib import asynccontextmanager
from typing import Optional
from uuid import UUID

import redis.asyncio as redis_async
import structlog

logger = structlog.get_logger(__name__)

ENTITY_PREFIX = "vigil:entity"
PROCESSED_PREFIX = "vigil:processed"
LOCK_PREFIX = "vigil:lock"


# Lua script for safe lock release: only delete if value matches token.
_RELEASE_LOCK_SCRIPT = """
if redis.call('get', KEYS[1]) == ARGV[1] then
  return redis.call('del', KEYS[1])
else
  return 0
end
"""


class EntityIndex:
    """Thin wrapper over redis.asyncio for the lookups the handler needs."""

    def __init__(
        self,
        client: redis_async.Redis,
        entity_ttl_seconds: int = 7200,
        idempotency_ttl_seconds: int = 86400,
        lock_ttl_seconds: int = 10,
    ):
        self.client = client
        self.entity_ttl = entity_ttl_seconds
        self.idempotency_ttl = idempotency_ttl_seconds
        self.lock_ttl = lock_ttl_seconds

    @classmethod
    async def from_url(
        cls,
        url: str,
        entity_ttl_seconds: int = 7200,
        idempotency_ttl_seconds: int = 86400,
        lock_ttl_seconds: int = 10,
    ) -> "EntityIndex":
        client = redis_async.from_url(url, decode_responses=True)
        await client.ping()
        return cls(
            client,
            entity_ttl_seconds=entity_ttl_seconds,
            idempotency_ttl_seconds=idempotency_ttl_seconds,
            lock_ttl_seconds=lock_ttl_seconds,
        )

    async def close(self) -> None:
        await self.client.aclose()

    # ── entity index ──────────────────────────────────────────────────────────

    @staticmethod
    def _entity_key(tenant_id: str, entity_type: str, entity_value: str) -> str:
        return f"{ENTITY_PREFIX}:{tenant_id}:{entity_type}:{entity_value.lower()}"

    async def lookup(
        self, tenant_id: str, entity_type: str, entity_value: str
    ) -> Optional[UUID]:
        raw = await self.client.get(self._entity_key(tenant_id, entity_type, entity_value))
        if not raw:
            return None
        try:
            return UUID(raw)
        except ValueError:
            return None

    async def lookup_any(
        self, tenant_id: str, entities: list[tuple[str, str]]
    ) -> Optional[UUID]:
        """Return the first attack_id for any of the supplied (type, value) pairs."""
        if not entities:
            return None
        keys = [self._entity_key(tenant_id, t, v) for t, v in entities]
        values = await self.client.mget(*keys)
        for v in values:
            if v:
                try:
                    return UUID(v)
                except ValueError:
                    continue
        return None

    async def bind(
        self,
        tenant_id: str,
        entities: list[tuple[str, str]],
        attack_id: UUID,
    ) -> None:
        if not entities:
            return
        async with self.client.pipeline(transaction=False) as pipe:
            for entity_type, entity_value in entities:
                key = self._entity_key(tenant_id, entity_type, entity_value)
                pipe.set(key, str(attack_id), ex=self.entity_ttl)
            await pipe.execute()

    # ── idempotency ───────────────────────────────────────────────────────────

    @staticmethod
    def _processed_key(tenant_id: str, event_id: str) -> str:
        return f"{PROCESSED_PREFIX}:{tenant_id}:{event_id}"

    async def mark_processed_if_new(self, tenant_id: str, event_id: str) -> bool:
        """
        Atomic SET NX. Returns True if this event was unseen (claim succeeded),
        False if it has already been processed.
        """
        key = self._processed_key(tenant_id, event_id)
        result = await self.client.set(key, "1", nx=True, ex=self.idempotency_ttl)
        return bool(result)

    async def is_processed(self, tenant_id: str, event_id: str) -> bool:
        return bool(await self.client.exists(self._processed_key(tenant_id, event_id)))

    async def unmark_processed(self, tenant_id: str, event_id: str) -> None:
        """Used to roll back the idempotency claim if processing fails."""
        await self.client.delete(self._processed_key(tenant_id, event_id))

    # ── distributed lock ──────────────────────────────────────────────────────

    @asynccontextmanager
    async def lock(
        self,
        tenant_id: str,
        lock_key: str,
        wait_seconds: float = 5.0,
        poll_interval: float = 0.05,
    ):
        """Best-effort distributed lock for the entity lookup+create critical section."""
        full_key = f"{LOCK_PREFIX}:{tenant_id}:{lock_key}"
        token = secrets.token_hex(16)
        deadline = asyncio.get_event_loop().time() + wait_seconds
        acquired = False
        while not acquired:
            acquired = bool(
                await self.client.set(full_key, token, nx=True, ex=self.lock_ttl)
            )
            if acquired:
                break
            if asyncio.get_event_loop().time() > deadline:
                raise TimeoutError(f"Failed to acquire lock {full_key} within {wait_seconds}s")
            await asyncio.sleep(poll_interval)
        try:
            yield
        finally:
            try:
                await self.client.eval(_RELEASE_LOCK_SCRIPT, 1, full_key, token)
            except Exception as e:
                logger.warning("entity_index.lock.release_failed", key=full_key, error=str(e))
