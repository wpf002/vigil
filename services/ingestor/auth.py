"""API-key authentication for the inbound /signals webhook.

Customers (and the Python SDK) authenticate with a Bearer `vgl_…` key — the
same keys the api service issues into the shared `api_keys` table. We validate
the key here and return its tenant_id, so the webhook is tenant-scoped by the
key itself (the request body's tenant_id is never trusted).

Hashing matches services/api/key_store.py: SHA-256 the raw key, then bcrypt the
digest; lookup is by the 8-char key_prefix. Verified keys are cached in-process
to avoid a bcrypt check on every call.
"""

from __future__ import annotations

import asyncio
import hashlib
from datetime import datetime, timezone
from typing import Optional

import asyncpg
import bcrypt
import jwt
import structlog
from fastapi import HTTPException

from .config import get_config


def _authenticate_jwt(token: str) -> str:
    """Validate a user JWT (HS256, shared AUTH_SECRET) and return its tenant_id.
    Lets the analyst UI call ingest/simulation endpoints with the same session
    token it uses everywhere else."""
    secret = get_config().auth_secret
    if not secret:
        raise HTTPException(status_code=401, detail="invalid credential")
    try:
        payload = jwt.decode(token, secret, algorithms=["HS256"])
    except Exception:
        raise HTTPException(status_code=401, detail="invalid token")
    tenant_id = payload.get("tenant_id")
    if not tenant_id:
        raise HTTPException(status_code=401, detail="token missing tenant_id")
    return str(tenant_id)

logger = structlog.get_logger(__name__)

_pool: Optional[asyncpg.Pool] = None
_pool_lock = asyncio.Lock()
# raw key -> tenant_id for already-verified keys (avoids per-call bcrypt)
_verified_cache: dict[str, str] = {}


def _verify(raw: str, key_hash: str) -> bool:
    if not raw or not key_hash:
        return False
    try:
        digest = hashlib.sha256(raw.encode("utf-8")).digest()
        return bcrypt.checkpw(digest, key_hash.encode("utf-8"))
    except (ValueError, TypeError):
        return False


async def _get_pool() -> asyncpg.Pool:
    global _pool
    if _pool is not None:
        return _pool
    async with _pool_lock:
        if _pool is None:
            dsn = get_config().database_url
            if not dsn:
                raise HTTPException(
                    status_code=503,
                    detail="signal ingest is not configured (no DATABASE_URL)",
                )
            _pool = await asyncpg.create_pool(dsn, min_size=1, max_size=5)
    return _pool


async def authenticate(authorization: Optional[str]) -> str:
    """Validate a `Authorization: Bearer vgl_…` header. Returns tenant_id.

    Raises HTTPException(401) on any auth failure, (503) if the key store is
    unreachable.
    """
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    raw = authorization[7:].strip()
    # Two accepted credentials: a vgl_ API key (machine/SDK) or a user JWT
    # (the analyst UI). Both resolve to a tenant.
    if not raw.startswith("vgl_"):
        return _authenticate_jwt(raw)

    cached = _verified_cache.get(raw)
    if cached is not None:
        return cached

    pool = await _get_pool()
    prefix = raw[:8]
    try:
        rows = await pool.fetch(
            "SELECT tenant_id, key_hash, revoked, expires_at "
            "FROM api_keys WHERE key_prefix = $1",
            prefix,
        )
    except Exception as e:  # pragma: no cover - infra failure
        logger.error("ingestor.auth.db_error", error=str(e))
        raise HTTPException(status_code=503, detail="key store unreachable")

    now = datetime.now(timezone.utc)
    for r in rows:
        if r["revoked"]:
            continue
        if r["expires_at"] is not None and r["expires_at"] < now:
            continue
        if _verify(raw, r["key_hash"]):
            tenant_id = str(r["tenant_id"])
            _verified_cache[raw] = tenant_id
            return tenant_id

    raise HTTPException(status_code=401, detail="invalid api key")


async def get_pool_optional() -> Optional[asyncpg.Pool]:
    """Best-effort pool accessor for read-only lookups (e.g. coverage report).
    Returns None instead of raising if the key store is not configured."""
    try:
        return await _get_pool()
    except Exception:
        return None


async def close_pool() -> None:
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None
