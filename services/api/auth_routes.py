"""HTTP handlers for /auth/*.

The store is a request-scoped dependency provided by main.py via dependency
injection so tests can swap a fake.
"""

from __future__ import annotations
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, EmailStr, Field

from .audit_logger import list_audit_log, log_event
from .config import get_config
from .key_store import (
    KeyStore,
    generate_api_key,
    hash_api_key,
)
from .password import (
    PasswordValidationError,
    generate_temporary_password,
    hash_password,
    hash_token,
    validate_password,
    verify_password,
    verify_token,
)
from .tokens import (
    TokenError,
    create_access_token,
    generate_refresh_token,
    refresh_token_expiry,
    verify_access_token,
)
from .user_store import UserRow, UserStore

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])
bearer_scheme = HTTPBearer(auto_error=False)


# ── request models ──────────────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    tenant_name: str = Field(min_length=1, max_length=200)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str


class LogoutRequest(BaseModel):
    refresh_token: str


class InviteRequest(BaseModel):
    email: EmailStr
    role: str = Field(default="analyst")


class StaffRegisterRequest(BaseModel):
    email: EmailStr
    password: str
    role: str = Field(default="vigil_analyst")
    registration_key: str


# ── response models ─────────────────────────────────────────────────────────

class UserResponse(BaseModel):
    user_id: UUID
    email: str
    role: str
    tenant_id: UUID


class MeResponse(BaseModel):
    user_id: UUID
    email: str
    role: str
    tenant_id: UUID
    last_login: Optional[datetime]


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    user: UserResponse


class RefreshResponse(BaseModel):
    access_token: str
    refresh_token: str


class InviteResponse(BaseModel):
    user_id: UUID
    email: str
    temporary_password: str


# ── store dependency (overridden in tests via app.dependency_overrides) ──────

def get_store(request: Request) -> UserStore:
    store: Optional[UserStore] = getattr(request.app.state, "user_store", None)
    if store is None:
        raise HTTPException(status_code=503, detail="Store not initialized")
    return store


# ── auth dependency ─────────────────────────────────────────────────────────

async def require_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    store: UserStore = Depends(get_store),
) -> UserRow:
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing bearer token",
        )
    try:
        claims = verify_access_token(credentials.credentials)
    except TokenError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
        )

    user = await store.get_user_by_id(UUID(claims.sub))
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )
    return user


async def require_admin(user: UserRow = Depends(require_user)) -> UserRow:
    if user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin role required",
        )
    return user


def get_key_store(request: Request) -> KeyStore:
    store: Optional[KeyStore] = getattr(request.app.state, "key_store", None)
    if store is None:
        raise HTTPException(status_code=503, detail="Key store not initialized")
    return store


# ── helpers ─────────────────────────────────────────────────────────────────

async def _issue_token_pair(store: UserStore, user: UserRow) -> tuple[str, str]:
    access = create_access_token(
        user_id=user.user_id,
        tenant_id=user.tenant_id,
        role=user.role,
        email=user.email,
    )
    refresh = generate_refresh_token()
    await store.create_refresh_token(
        user_id=user.user_id,
        token_hash=hash_token(refresh),
        expires_at=refresh_token_expiry(),
    )
    return access, refresh


def _user_response(user: UserRow) -> UserResponse:
    return UserResponse(
        user_id=user.user_id,
        email=user.email,
        role=user.role,
        tenant_id=user.tenant_id,
    )


# ── routes ──────────────────────────────────────────────────────────────────

@router.post("/register", response_model=TokenPair)
async def register(req: RegisterRequest, request: Request, store: UserStore = Depends(get_store)):
    try:
        validate_password(req.password)
    except PasswordValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))

    existing = await store.get_user_by_email(req.email)
    if existing is not None:
        raise HTTPException(status_code=409, detail="Email already registered")

    _, user = await store.create_tenant_with_admin(
        tenant_name=req.tenant_name,
        email=req.email,
        password_hash=hash_password(req.password),
    )
    access, refresh = await _issue_token_pair(store, user)
    logger.info("auth.register", user_id=str(user.user_id), tenant_id=str(user.tenant_id))
    await log_event(
        store.pool, tenant_id=user.tenant_id, user_id=user.user_id,
        event_type="user.created", resource_type="user",
        resource_id=str(user.user_id), request=request,
    )
    return TokenPair(access_token=access, refresh_token=refresh, user=_user_response(user))


@router.post("/login", response_model=TokenPair)
async def login(req: LoginRequest, request: Request, store: UserStore = Depends(get_store)):
    user = await store.get_user_by_email(req.email)
    # Constant-message failure for invalid email + wrong password to avoid
    # leaking which one is wrong.
    if user is None or not user.is_active or not verify_password(req.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    now = datetime.now(timezone.utc)
    await store.update_last_login(user.user_id, now)
    user.last_login = now

    access, refresh = await _issue_token_pair(store, user)
    logger.info("auth.login", user_id=str(user.user_id))
    await log_event(
        store.pool, tenant_id=user.tenant_id, user_id=user.user_id,
        event_type="user.login", resource_type="user",
        resource_id=str(user.user_id), request=request,
    )
    return TokenPair(access_token=access, refresh_token=refresh, user=_user_response(user))


@router.post("/refresh", response_model=RefreshResponse)
async def refresh(req: RefreshRequest, store: UserStore = Depends(get_store)):
    """Refresh-token rotation: revoke the presented token, issue a new pair.

    The presented token is opaque — we don't know which user it belongs to
    until we hash-compare against active rows. Fanning out across all active
    rows would be expensive; in practice attackers don't have a user hint, so
    we rely on token entropy (64 bytes) to make blind guesses infeasible.
    Lookups are O(active tokens), but per-user that's typically <5.

    Production hardening: store a non-secret prefix (e.g. first 8 chars) as
    a lookup key. Skipping for now — the table is small and bcrypt verifies
    are bounded by user count, not tenant count.
    """
    candidate = req.refresh_token
    if not candidate or len(candidate) < 32:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    # Iterate over all users to find a matching active token. For a small
    # MVP user base this is fine; replace with a token-prefix lookup when
    # the active token count grows past O(thousands).
    matched_user: Optional[UserRow] = None
    matched_token_id: Optional[UUID] = None

    async with store.pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT rt.token_id, rt.token_hash, rt.user_id
            FROM refresh_tokens rt
            WHERE rt.revoked = FALSE AND rt.expires_at > now()
            """
        )

    for row in rows:
        if verify_token(candidate, row["token_hash"]):
            matched_token_id = row["token_id"]
            matched_user = await store.get_user_by_id(row["user_id"])
            break

    if matched_user is None or matched_token_id is None or not matched_user.is_active:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    await store.revoke_refresh_token(matched_token_id)
    access, new_refresh = await _issue_token_pair(store, matched_user)
    logger.info("auth.refresh", user_id=str(matched_user.user_id))
    return RefreshResponse(access_token=access, refresh_token=new_refresh)


@router.post("/logout")
async def logout(
    req: LogoutRequest,
    request: Request,
    user: UserRow = Depends(require_user),
    store: UserStore = Depends(get_store),
):
    """Revoke the provided refresh token. Access token expires on its own."""
    tokens = await store.list_active_refresh_tokens(user.user_id)
    for t in tokens:
        if verify_token(req.refresh_token, t.token_hash):
            await store.revoke_refresh_token(t.token_id)
            break
    await log_event(
        store.pool, tenant_id=user.tenant_id, user_id=user.user_id,
        event_type="user.logout", resource_type="user",
        resource_id=str(user.user_id), request=request,
    )
    return {"message": "logged out"}


@router.get("/me", response_model=MeResponse)
async def me(user: UserRow = Depends(require_user)):
    return MeResponse(
        user_id=user.user_id,
        email=user.email,
        role=user.role,
        tenant_id=user.tenant_id,
        last_login=user.last_login,
    )


@router.post("/users/invite", response_model=InviteResponse)
async def invite(
    req: InviteRequest,
    admin: UserRow = Depends(require_admin),
    store: UserStore = Depends(get_store),
):
    allowed_roles = ("analyst", "admin", "vigil_analyst", "vigil_admin")
    if req.role not in allowed_roles:
        raise HTTPException(
            status_code=400,
            detail=f"role must be one of {', '.join(allowed_roles)}",
        )

    existing = await store.get_user_by_email(req.email)
    if existing is not None:
        raise HTTPException(status_code=409, detail="Email already registered")

    temp_password = generate_temporary_password()
    new_user = await store.create_user(
        tenant_id=admin.tenant_id,
        email=req.email,
        password_hash=hash_password(temp_password),
        role=req.role,
    )
    logger.info(
        "auth.invite",
        admin_id=str(admin.user_id),
        invited_id=str(new_user.user_id),
        tenant_id=str(admin.tenant_id),
    )
    return InviteResponse(
        user_id=new_user.user_id,
        email=new_user.email,
        temporary_password=temp_password,
    )


@router.post("/register/staff", response_model=TokenPair)
async def register_staff(req: StaffRegisterRequest, store: UserStore = Depends(get_store)):
    """Bootstrap registration for VIGIL staff (analyst-portal users).

    Gated on STAFF_REGISTRATION_KEY config — the request body must include
    that exact value. Empty config disables this endpoint entirely. After
    bootstrap, additional staff should be onboarded via /auth/users/invite
    by an existing admin.
    """
    cfg = get_config()
    if not cfg.staff_registration_key:
        raise HTTPException(status_code=403, detail="Staff registration disabled")
    if req.registration_key != cfg.staff_registration_key:
        raise HTTPException(status_code=403, detail="Invalid registration key")
    if req.role not in ("vigil_analyst", "vigil_admin"):
        raise HTTPException(
            status_code=400,
            detail="role must be 'vigil_analyst' or 'vigil_admin'",
        )

    try:
        validate_password(req.password)
    except PasswordValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))

    existing = await store.get_user_by_email(req.email)
    if existing is not None:
        raise HTTPException(status_code=409, detail="Email already registered")

    tenant = await store.get_or_create_tenant_by_name(cfg.platform_tenant_name)
    user = await store.create_user(
        tenant_id=tenant.tenant_id,
        email=req.email,
        password_hash=hash_password(req.password),
        role=req.role,
    )
    access, refresh = await _issue_token_pair(store, user)
    logger.info(
        "auth.register_staff",
        user_id=str(user.user_id),
        role=user.role,
        platform_tenant_id=str(tenant.tenant_id),
    )
    return TokenPair(
        access_token=access,
        refresh_token=refresh,
        user=_user_response(user),
    )


# ── API keys ────────────────────────────────────────────────────────────────


VALID_SCOPES = {
    "read:attacks", "read:detections", "write:signals", "read:reports",
}


class APIKeyCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    scopes: list[str] = Field(default_factory=list)
    expires_at: Optional[datetime] = None


class APIKeyCreatedResponse(BaseModel):
    key_id: UUID
    name: str
    key_prefix: str
    scopes: list[str]
    raw_key: str
    expires_at: Optional[datetime]


class APIKeyResponse(BaseModel):
    key_id: UUID
    name: str
    key_prefix: str
    scopes: list[str]
    last_used_at: Optional[datetime]
    expires_at: Optional[datetime]
    revoked: bool
    created_at: datetime


@router.post("/api-keys", response_model=APIKeyCreatedResponse)
async def create_api_key_route(
    req: APIKeyCreateRequest,
    user: UserRow = Depends(require_user),
    keys: KeyStore = Depends(get_key_store),
):
    invalid = [s for s in req.scopes if s not in VALID_SCOPES]
    if invalid:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid scopes: {', '.join(invalid)}",
        )

    raw, prefix = generate_api_key()
    row = await keys.create_api_key(
        tenant_id=user.tenant_id, created_by=user.user_id,
        name=req.name, key_prefix=prefix, key_hash=hash_api_key(raw),
        scopes=req.scopes, expires_at=req.expires_at,
    )
    logger.info(
        "auth.api_key.created",
        key_id=str(row.key_id), tenant_id=str(user.tenant_id),
        prefix=prefix,
    )
    await log_event(
        keys.pool, tenant_id=user.tenant_id, user_id=user.user_id,
        event_type="api_key.created", resource_type="api_key",
        resource_id=str(row.key_id),
        detail={"name": row.name, "scopes": row.scopes, "prefix": row.key_prefix},
    )
    return APIKeyCreatedResponse(
        key_id=row.key_id, name=row.name, key_prefix=row.key_prefix,
        scopes=row.scopes, raw_key=raw, expires_at=row.expires_at,
    )


@router.get("/api-keys", response_model=list[APIKeyResponse])
async def list_api_keys_route(
    user: UserRow = Depends(require_user),
    keys: KeyStore = Depends(get_key_store),
):
    rows = await keys.list_api_keys(user.tenant_id)
    return [
        APIKeyResponse(
            key_id=r.key_id, name=r.name, key_prefix=r.key_prefix,
            scopes=r.scopes, last_used_at=r.last_used_at,
            expires_at=r.expires_at, revoked=r.revoked, created_at=r.created_at,
        )
        for r in rows
    ]


@router.delete("/api-keys/{key_id}")
async def revoke_api_key_route(
    key_id: UUID,
    user: UserRow = Depends(require_user),
    keys: KeyStore = Depends(get_key_store),
):
    revoked = await keys.revoke_api_key(key_id=key_id, tenant_id=user.tenant_id)
    if not revoked:
        raise HTTPException(status_code=404, detail="Key not found")
    logger.info("auth.api_key.revoked", key_id=str(key_id), tenant_id=str(user.tenant_id))
    await log_event(
        keys.pool, tenant_id=user.tenant_id, user_id=user.user_id,
        event_type="api_key.revoked", resource_type="api_key",
        resource_id=str(key_id),
    )
    return {"revoked": True}


# ── Audit log ───────────────────────────────────────────────────────────────


@router.get("/audit-log")
async def get_audit_log(
    days: int = 30,
    event_type: Optional[str] = None,
    user_id: Optional[UUID] = None,
    user: UserRow = Depends(require_user),
    store: UserStore = Depends(get_store),
):
    """Returns the tenant's audit_log entries. Append-only — there is no
    DELETE counterpart by design (SOC 2 retention)."""
    rows = await list_audit_log(
        store.pool, tenant_id=user.tenant_id, user_id=user_id,
        event_type=event_type, days=days,
    )
    return rows


# ── Webhooks ────────────────────────────────────────────────────────────────


VALID_WEBHOOK_EVENTS = {
    "attack.created", "attack.updated", "attack.escalated",
    "attack.resolved", "playbook.paused",
}


class WebhookCreateRequest(BaseModel):
    url: str
    secret: str = Field(min_length=8)
    events: list[str]


class WebhookResponse(BaseModel):
    webhook_id: UUID
    url: str
    events: list[str]
    active: bool
    last_fired_at: Optional[datetime]
    failure_count: int
    created_at: datetime


webhook_router = APIRouter(prefix="/webhooks", tags=["webhooks"])


@webhook_router.post("", response_model=WebhookResponse)
async def create_webhook_route(
    req: WebhookCreateRequest,
    user: UserRow = Depends(require_user),
    keys: KeyStore = Depends(get_key_store),
):
    invalid = [e for e in req.events if e not in VALID_WEBHOOK_EVENTS]
    if invalid:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid events: {', '.join(invalid)}",
        )
    if not req.events:
        raise HTTPException(status_code=400, detail="At least one event required")

    row = await keys.create_webhook(
        tenant_id=user.tenant_id, url=req.url, secret=req.secret, events=req.events,
    )
    logger.info(
        "webhook.registered", webhook_id=str(row.webhook_id), tenant_id=str(user.tenant_id),
    )
    await log_event(
        keys.pool, tenant_id=user.tenant_id, user_id=user.user_id,
        event_type="webhook.registered", resource_type="webhook",
        resource_id=str(row.webhook_id),
        detail={"url": row.url, "events": row.events},
    )
    return WebhookResponse(
        webhook_id=row.webhook_id, url=row.url, events=row.events,
        active=row.active, last_fired_at=row.last_fired_at,
        failure_count=row.failure_count, created_at=row.created_at,
    )


@webhook_router.get("", response_model=list[WebhookResponse])
async def list_webhooks_route(
    user: UserRow = Depends(require_user),
    keys: KeyStore = Depends(get_key_store),
):
    rows = await keys.list_webhooks(user.tenant_id)
    return [
        WebhookResponse(
            webhook_id=r.webhook_id, url=r.url, events=r.events,
            active=r.active, last_fired_at=r.last_fired_at,
            failure_count=r.failure_count, created_at=r.created_at,
        )
        for r in rows
    ]


@webhook_router.delete("/{webhook_id}")
async def delete_webhook_route(
    webhook_id: UUID,
    user: UserRow = Depends(require_user),
    keys: KeyStore = Depends(get_key_store),
):
    deleted = await keys.delete_webhook(webhook_id=webhook_id, tenant_id=user.tenant_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Webhook not found")
    return {"deleted": True}


@webhook_router.post("/{webhook_id}/test")
async def test_webhook_route(
    webhook_id: UUID,
    user: UserRow = Depends(require_user),
    keys: KeyStore = Depends(get_key_store),
):
    """Fire a test payload to the webhook URL. Returns the HTTP status code
    or an error string. Does not update last_fired_at — this is a probe."""
    import httpx
    import json
    from .key_store import hmac_sign

    wh = await keys.get_webhook(webhook_id=webhook_id, tenant_id=user.tenant_id)
    if wh is None:
        raise HTTPException(status_code=404, detail="Webhook not found")

    body = {
        "event": "test",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tenant_id": str(user.tenant_id),
        "data": {"message": "VIGIL webhook test"},
    }
    payload = json.dumps(body).encode("utf-8")
    sig = hmac_sign(wh.secret, payload)
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                wh.url,
                content=payload,
                headers={
                    "Content-Type": "application/json",
                    "X-VIGIL-Event": "test",
                    "X-VIGIL-Signature": f"sha256={sig}",
                },
            )
        return {"status_code": resp.status_code, "ok": resp.status_code < 400}
    except Exception as e:
        return {"status_code": None, "ok": False, "error": str(e)}
