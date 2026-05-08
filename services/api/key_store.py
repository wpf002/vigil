"""asyncpg-backed access for api_keys + webhooks.

API keys: stored as bcrypt hashes of the SHA-256 of the raw token (same
trick as refresh_tokens — bypasses the 72-byte bcrypt input limit). Raw
token is returned exactly once at creation, never again.

Webhooks: HMAC secret stored verbatim and never returned after creation.
"""

from __future__ import annotations
import hmac
import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime
from typing import Optional
from uuid import UUID

import asyncpg


KEY_PREFIX_LITERAL = "vgl_"


def generate_api_key() -> tuple[str, str]:
    """Returns (raw_key, key_prefix). Raw key is shown once and never stored."""
    body = secrets.token_hex(24)  # 48-char hex = ~192 bits of entropy
    raw = f"{KEY_PREFIX_LITERAL}{body}"
    return raw, raw[:8]


def hash_api_key(raw: str) -> str:
    """SHA-256 the raw key then bcrypt the digest."""
    import bcrypt

    digest = hashlib.sha256(raw.encode("utf-8")).digest()
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(digest, salt).decode("utf-8")


def verify_api_key(raw: str, key_hash: str) -> bool:
    if not raw or not key_hash:
        return False
    import bcrypt

    try:
        digest = hashlib.sha256(raw.encode("utf-8")).digest()
        return bcrypt.checkpw(digest, key_hash.encode("utf-8"))
    except (ValueError, TypeError):
        return False


@dataclass
class APIKeyRow:
    key_id: UUID
    tenant_id: UUID
    created_by: UUID
    name: str
    key_prefix: str
    key_hash: str
    scopes: list[str]
    last_used_at: Optional[datetime]
    expires_at: Optional[datetime]
    revoked: bool
    created_at: datetime


@dataclass
class WebhookRow:
    webhook_id: UUID
    tenant_id: UUID
    url: str
    secret: str
    events: list[str]
    active: bool
    last_fired_at: Optional[datetime]
    failure_count: int
    created_at: datetime


def _api_key_row(row) -> APIKeyRow:
    return APIKeyRow(
        key_id=row["key_id"],
        tenant_id=row["tenant_id"],
        created_by=row["created_by"],
        name=row["name"],
        key_prefix=row["key_prefix"],
        key_hash=row["key_hash"],
        scopes=list(row["scopes"] or []),
        last_used_at=row.get("last_used_at"),
        expires_at=row.get("expires_at"),
        revoked=row["revoked"],
        created_at=row["created_at"],
    )


def _webhook_row(row) -> WebhookRow:
    return WebhookRow(
        webhook_id=row["webhook_id"],
        tenant_id=row["tenant_id"],
        url=row["url"],
        secret=row["secret"],
        events=list(row["events"] or []),
        active=row["active"],
        last_fired_at=row.get("last_fired_at"),
        failure_count=row["failure_count"],
        created_at=row["created_at"],
    )


class KeyStore:
    """Owns api_keys + webhooks tables."""

    def __init__(self, pool: asyncpg.Pool):
        self.pool = pool

    # ── api_keys ──────────────────────────────────────────────────────────

    async def create_api_key(
        self, *, tenant_id: UUID, created_by: UUID, name: str,
        key_prefix: str, key_hash: str, scopes: list[str],
        expires_at: Optional[datetime] = None,
    ) -> APIKeyRow:
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO api_keys (
                    tenant_id, created_by, name, key_prefix, key_hash,
                    scopes, expires_at
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                RETURNING *
                """,
                tenant_id, created_by, name, key_prefix, key_hash,
                scopes, expires_at,
            )
        return _api_key_row(row)

    async def list_api_keys(self, tenant_id: UUID) -> list[APIKeyRow]:
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT * FROM api_keys
                 WHERE tenant_id = $1
                 ORDER BY created_at DESC
                """,
                tenant_id,
            )
        return [_api_key_row(r) for r in rows]

    async def revoke_api_key(self, *, key_id: UUID, tenant_id: UUID) -> bool:
        async with self.pool.acquire() as conn:
            result = await conn.execute(
                """
                UPDATE api_keys SET revoked = TRUE
                 WHERE key_id = $1 AND tenant_id = $2
                """,
                key_id, tenant_id,
            )
        return result.endswith("1")

    async def list_active_api_keys(self) -> list[APIKeyRow]:
        """All non-revoked, non-expired keys across all tenants. Used by the
        bearer-token auth path that needs to hash-compare an incoming key."""
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT * FROM api_keys
                 WHERE revoked = FALSE
                   AND (expires_at IS NULL OR expires_at > now())
                """
            )
        return [_api_key_row(r) for r in rows]

    async def list_active_api_keys_by_prefix(self, prefix: str) -> list[APIKeyRow]:
        """Narrow scan by the 8-char prefix. Reduces the number of bcrypt
        verifies on a multi-tenant fleet."""
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT * FROM api_keys
                 WHERE key_prefix = $1
                   AND revoked = FALSE
                   AND (expires_at IS NULL OR expires_at > now())
                """,
                prefix,
            )
        return [_api_key_row(r) for r in rows]

    async def touch_last_used(self, key_id: UUID, when: datetime) -> None:
        async with self.pool.acquire() as conn:
            await conn.execute(
                "UPDATE api_keys SET last_used_at = $2 WHERE key_id = $1",
                key_id, when,
            )

    # ── webhooks ──────────────────────────────────────────────────────────

    async def create_webhook(
        self, *, tenant_id: UUID, url: str, secret: str, events: list[str]
    ) -> WebhookRow:
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO webhooks (tenant_id, url, secret, events)
                VALUES ($1, $2, $3, $4)
                RETURNING *
                """,
                tenant_id, url, secret, events,
            )
        return _webhook_row(row)

    async def list_webhooks(self, tenant_id: UUID) -> list[WebhookRow]:
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT * FROM webhooks WHERE tenant_id = $1 ORDER BY created_at DESC",
                tenant_id,
            )
        return [_webhook_row(r) for r in rows]

    async def get_webhook(self, *, webhook_id: UUID, tenant_id: UUID) -> Optional[WebhookRow]:
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM webhooks WHERE webhook_id = $1 AND tenant_id = $2",
                webhook_id, tenant_id,
            )
        return _webhook_row(row) if row else None

    async def delete_webhook(self, *, webhook_id: UUID, tenant_id: UUID) -> bool:
        async with self.pool.acquire() as conn:
            result = await conn.execute(
                "DELETE FROM webhooks WHERE webhook_id = $1 AND tenant_id = $2",
                webhook_id, tenant_id,
            )
        return result.endswith("1")

    async def list_active_webhooks_for_event(self, *, tenant_id: UUID, event: str) -> list[WebhookRow]:
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT * FROM webhooks
                 WHERE tenant_id = $1 AND active = TRUE AND $2 = ANY(events)
                """,
                tenant_id, event,
            )
        return [_webhook_row(r) for r in rows]

    async def record_webhook_success(self, webhook_id: UUID, when: datetime) -> None:
        async with self.pool.acquire() as conn:
            await conn.execute(
                """
                UPDATE webhooks
                   SET last_fired_at = $2, failure_count = 0
                 WHERE webhook_id = $1
                """,
                webhook_id, when,
            )

    async def record_webhook_failure(self, webhook_id: UUID) -> int:
        """Increment failure_count; auto-deactivate at 10. Returns new count."""
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                UPDATE webhooks
                   SET failure_count = failure_count + 1,
                       active = CASE WHEN failure_count + 1 >= 10 THEN FALSE ELSE active END
                 WHERE webhook_id = $1
                 RETURNING failure_count
                """,
                webhook_id,
            )
        return int(row["failure_count"]) if row else 0


def hmac_sign(secret: str, payload: bytes) -> str:
    return hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()


def hmac_verify(secret: str, payload: bytes, signature: str) -> bool:
    expected = hmac_sign(secret, payload)
    # Strip any "sha256=" prefix the customer may include.
    presented = signature.split("=", 1)[1] if "=" in signature else signature
    return hmac.compare_digest(expected, presented)
