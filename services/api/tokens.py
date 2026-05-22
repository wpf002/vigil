"""JWT access tokens and opaque refresh tokens."""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from uuid import UUID

import jwt

from .config import get_config

JWT_ALGORITHM = "HS256"


class TokenError(Exception):
    """Raised on any token decode/verify failure. Detail is safe to surface."""


@dataclass
class AccessTokenClaims:
    sub: str          # user_id
    tenant_id: str
    role: str
    email: str
    exp: int
    iat: int


def create_access_token(
    *,
    user_id: UUID | str,
    tenant_id: UUID | str,
    role: str,
    email: str,
    ttl_minutes: Optional[int] = None,
) -> str:
    cfg = get_config()
    now = datetime.now(timezone.utc)
    minutes = ttl_minutes if ttl_minutes is not None else cfg.access_token_ttl_minutes
    payload = {
        "sub": str(user_id),
        "tenant_id": str(tenant_id),
        "role": role,
        "email": email,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=minutes)).timestamp()),
    }
    return jwt.encode(payload, cfg.auth_secret, algorithm=JWT_ALGORITHM)


def verify_access_token(token: str) -> AccessTokenClaims:
    cfg = get_config()
    try:
        payload: dict[str, Any] = jwt.decode(
            token, cfg.auth_secret, algorithms=[JWT_ALGORITHM]
        )
    except jwt.ExpiredSignatureError as e:
        raise TokenError("Token expired") from e
    except jwt.InvalidTokenError as e:
        raise TokenError("Invalid token") from e

    required = ("sub", "tenant_id", "role", "email", "exp", "iat")
    missing = [k for k in required if k not in payload]
    if missing:
        raise TokenError(f"Token missing claims: {','.join(missing)}")

    return AccessTokenClaims(
        sub=str(payload["sub"]),
        tenant_id=str(payload["tenant_id"]),
        role=str(payload["role"]),
        email=str(payload["email"]),
        exp=int(payload["exp"]),
        iat=int(payload["iat"]),
    )


def generate_refresh_token() -> str:
    """Cryptographically random hex string."""
    return secrets.token_hex(64)


def refresh_token_expiry() -> datetime:
    cfg = get_config()
    return datetime.now(timezone.utc) + timedelta(days=cfg.refresh_token_ttl_days)
