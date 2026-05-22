"""asyncpg-backed access for tenants, users, and refresh tokens.

No ORM. Raw SQL only. The store is thin — request shaping happens in
auth_routes.py.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Optional
from uuid import UUID

import asyncpg
import structlog

logger = structlog.get_logger(__name__)


@dataclass
class TenantRow:
    tenant_id: UUID
    name: str
    created_at: datetime


@dataclass
class UserRow:
    user_id: UUID
    tenant_id: UUID
    email: str
    password_hash: str
    role: str
    is_active: bool
    created_at: datetime
    last_login: Optional[datetime]
    onboarding_complete: bool = False


@dataclass
class RefreshTokenRow:
    token_id: UUID
    user_id: UUID
    token_hash: str
    expires_at: datetime
    revoked: bool
    created_at: datetime


class UserStore:
    """Thin asyncpg wrapper. Caller owns the pool lifecycle."""

    def __init__(self, pool: asyncpg.Pool):
        self.pool = pool

    @classmethod
    async def from_dsn(cls, dsn: str, min_size: int = 2, max_size: int = 10) -> "UserStore":
        pool = await asyncpg.create_pool(dsn, min_size=min_size, max_size=max_size)
        return cls(pool)

    async def close(self) -> None:
        await self.pool.close()

    # ── tenants + users ─────────────────────────────────────────────────────

    async def create_tenant_with_admin(
        self, *, tenant_name: str, email: str, password_hash: str
    ) -> tuple[TenantRow, UserRow]:
        """Single-transaction create. Used by /auth/register."""
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                tenant = await conn.fetchrow(
                    "INSERT INTO tenants (name) VALUES ($1) "
                    "RETURNING tenant_id, name, created_at",
                    tenant_name,
                )
                user = await conn.fetchrow(
                    """
                    INSERT INTO users (tenant_id, email, password_hash, role)
                    VALUES ($1, $2, $3, 'admin')
                    RETURNING user_id, tenant_id, email, password_hash, role,
                              is_active, created_at, last_login
                    """,
                    tenant["tenant_id"],
                    email,
                    password_hash,
                )
        return _tenant_row(tenant), _user_row(user)

    async def get_or_create_tenant_by_name(self, name: str) -> TenantRow:
        """Idempotent tenant lookup. Used to host VIGIL staff under a single
        platform tenant without forcing a new tenant per registration.
        """
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT tenant_id, name, created_at FROM tenants WHERE name = $1",
                name,
            )
            if row is None:
                row = await conn.fetchrow(
                    "INSERT INTO tenants (name) VALUES ($1) "
                    "RETURNING tenant_id, name, created_at",
                    name,
                )
        return _tenant_row(row)

    async def create_user(
        self,
        *,
        tenant_id: UUID,
        email: str,
        password_hash: str,
        role: str,
    ) -> UserRow:
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO users (tenant_id, email, password_hash, role)
                VALUES ($1, $2, $3, $4)
                RETURNING user_id, tenant_id, email, password_hash, role,
                          is_active, created_at, last_login
                """,
                tenant_id,
                email,
                password_hash,
                role,
            )
        return _user_row(row)

    async def get_user_by_email(self, email: str) -> Optional[UserRow]:
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT user_id, tenant_id, email, password_hash, role, "
                "is_active, created_at, last_login FROM users WHERE email = $1",
                email,
            )
        return _user_row(row) if row else None

    async def get_user_by_id(self, user_id: UUID) -> Optional[UserRow]:
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT user_id, tenant_id, email, password_hash, role, "
                "is_active, created_at, last_login FROM users WHERE user_id = $1",
                user_id,
            )
        return _user_row(row) if row else None

    async def mark_onboarding_complete(self, user_id: UUID) -> None:
        async with self.pool.acquire() as conn:
            await conn.execute(
                "UPDATE users SET onboarding_complete = TRUE WHERE user_id = $1",
                user_id,
            )

    async def update_last_login(self, user_id: UUID, when: datetime) -> None:
        async with self.pool.acquire() as conn:
            await conn.execute(
                "UPDATE users SET last_login = $2 WHERE user_id = $1",
                user_id,
                when,
            )

    # ── refresh tokens ──────────────────────────────────────────────────────

    async def create_refresh_token(
        self, *, user_id: UUID, token_hash: str, expires_at: datetime
    ) -> RefreshTokenRow:
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
                VALUES ($1, $2, $3)
                RETURNING token_id, user_id, token_hash, expires_at, revoked, created_at
                """,
                user_id,
                token_hash,
                expires_at,
            )
        return _refresh_row(row)

    async def list_active_refresh_tokens(self, user_id: UUID) -> list[RefreshTokenRow]:
        """Returns non-revoked, non-expired refresh tokens for the user.

        Refresh-token verify must hash-compare each row because the raw token
        is only known to the client, never stored. Most users have one active
        token at a time, so this list is small.
        """
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT token_id, user_id, token_hash, expires_at, revoked, created_at
                FROM refresh_tokens
                WHERE user_id = $1 AND revoked = FALSE AND expires_at > now()
                """,
                user_id,
            )
        return [_refresh_row(r) for r in rows]

    async def revoke_refresh_token(self, token_id: UUID) -> None:
        async with self.pool.acquire() as conn:
            await conn.execute(
                "UPDATE refresh_tokens SET revoked = TRUE WHERE token_id = $1",
                token_id,
            )


def _tenant_row(row) -> TenantRow:
    return TenantRow(
        tenant_id=row["tenant_id"],
        name=row["name"],
        created_at=row["created_at"],
    )


def _user_row(row) -> UserRow:
    return UserRow(
        user_id=row["user_id"],
        tenant_id=row["tenant_id"],
        email=row["email"],
        password_hash=row["password_hash"],
        role=row["role"],
        is_active=row["is_active"],
        created_at=row["created_at"],
        last_login=row["last_login"],
        onboarding_complete=bool(row.get("onboarding_complete") if isinstance(row, dict) else _safe_get(row, "onboarding_complete", False)),
    )


def _safe_get(row, key, default):
    try:
        v = row[key]
        return default if v is None else v
    except (KeyError, IndexError, TypeError):
        return default


def _refresh_row(row) -> RefreshTokenRow:
    return RefreshTokenRow(
        token_id=row["token_id"],
        user_id=row["user_id"],
        token_hash=row["token_hash"],
        expires_at=row["expires_at"],
        revoked=row["revoked"],
        created_at=row["created_at"],
    )
