"""JWT verification for the analyst-portal.

Distinct from attack-state-engine's auth: only roles ``vigil_analyst`` and
``vigil_admin`` may access this service. Customer-tier roles (analyst, admin)
get 403, even with a valid token, since they shouldn't see other tenants'
queues.
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

VIGIL_STAFF_ROLES = {"vigil_analyst", "vigil_admin"}
VIGIL_ADMIN_ROLE = "vigil_admin"


@dataclass
class StaffPrincipal:
    user_id: str
    email: Optional[str]
    role: str
    tenant_id: Optional[str] = None  # The customer tenant the call targets.


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={"error": "Unauthorized", "detail": detail},
    )


def _forbidden(detail: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail={"error": "Forbidden", "detail": detail},
    )


async def get_staff_principal(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> StaffPrincipal:
    cfg = get_config()
    environment = (os.getenv("ENVIRONMENT") or cfg.environment or "production").lower()

    # Dev-only bypass: X-Staff-Role header marks the caller as VIGIL staff
    # without a real JWT. Useful for local UI work before staff registration
    # is wired into the auth flow.
    if credentials is None and environment == "development":
        dev_role = request.headers.get("X-Staff-Role")
        dev_user = request.headers.get("X-Staff-Id")
        if dev_role in VIGIL_STAFF_ROLES and dev_user:
            return StaffPrincipal(user_id=dev_user, email=None, role=dev_role)

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

    role = str(payload.get("role") or "")
    if role not in VIGIL_STAFF_ROLES:
        raise _forbidden("Staff role required")

    user_id = payload.get("sub")
    if not user_id:
        raise _unauthorized("Token missing sub")

    request.state.principal = StaffPrincipal(
        user_id=str(user_id),
        email=payload.get("email"),
        role=role,
    )
    return request.state.principal


async def require_admin(
    principal: StaffPrincipal = Depends(get_staff_principal),
) -> StaffPrincipal:
    if principal.role != VIGIL_ADMIN_ROLE:
        raise _forbidden("vigil_admin role required")
    return principal
