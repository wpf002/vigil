"""
JWT authentication stub.

TODO: replace with real Clerk JWKS verification (use PyJWT + JWKS fetch).
For now this decodes the token unverified, extracts `sub` and `azp`,
and uses `sub` as tenant_id. Anyone with a forged token can call the API,
so do not deploy this stub to production.
"""

from __future__ import annotations
import base64
import json
from dataclasses import dataclass
from typing import Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

bearer_scheme = HTTPBearer(auto_error=False)


@dataclass
class TenantPrincipal:
    tenant_id: str
    user_id: str
    azp: Optional[str] = None


def _decode_jwt_unverified(token: str) -> dict:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Malformed JWT")
    payload_b64 = parts[1] + "=" * (-len(parts[1]) % 4)
    return json.loads(base64.urlsafe_b64decode(payload_b64))


async def get_principal(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> TenantPrincipal:
    # Dev mode: allow X-Tenant-Id header without a token.
    dev_tenant = request.headers.get("X-Tenant-Id")
    if credentials is None and dev_tenant:
        return TenantPrincipal(tenant_id=dev_tenant, user_id=dev_tenant)

    if credentials is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token")

    try:
        claims = _decode_jwt_unverified(credentials.credentials)
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid JWT")

    sub = claims.get("sub")
    if not sub:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="JWT missing sub claim")

    return TenantPrincipal(
        tenant_id=str(sub),
        user_id=str(sub),
        azp=claims.get("azp"),
    )
