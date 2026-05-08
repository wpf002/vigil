"""JWT verification for the detection-engine.

Mirrors attack-state-engine/auth.py: same HS256 secret as services/api,
same dev-only X-Tenant-Id bypass gated on ENVIRONMENT=development.
"""

from __future__ import annotations
import os
from dataclasses import dataclass
from typing import Optional

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .config import get_config

bearer_scheme = HTTPBearer(auto_error=False)
JWT_ALGORITHM = "HS256"


@dataclass
class TenantPrincipal:
    tenant_id: str
    user_id: str
    role: str = "analyst"
    email: Optional[str] = None


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={"error": "Unauthorized", "detail": detail},
    )


async def get_principal(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> TenantPrincipal:
    cfg = get_config()
    environment = (os.getenv("ENVIRONMENT") or cfg.environment or "production").lower()

    if credentials is None and environment == "development":
        dev_tenant = request.headers.get("X-Tenant-Id")
        if dev_tenant:
            return TenantPrincipal(tenant_id=dev_tenant, user_id=dev_tenant, role="admin")

    if credentials is None:
        raise _unauthorized("Missing bearer token")

    try:
        payload = jwt.decode(
            credentials.credentials,
            cfg.auth_secret,
            algorithms=[JWT_ALGORITHM],
        )
    except jwt.ExpiredSignatureError:
        raise _unauthorized("Token expired")
    except jwt.InvalidTokenError:
        raise _unauthorized("Invalid token")

    tenant_id = payload.get("tenant_id")
    user_id = payload.get("sub")
    if not tenant_id or not user_id:
        raise _unauthorized("Token missing tenant_id or sub")

    request.state.principal = TenantPrincipal(
        tenant_id=str(tenant_id),
        user_id=str(user_id),
        role=str(payload.get("role", "analyst")),
        email=payload.get("email"),
    )
    return request.state.principal


async def require_admin(
    principal: TenantPrincipal = Depends(get_principal),
) -> TenantPrincipal:
    if principal.role != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")
    return principal
