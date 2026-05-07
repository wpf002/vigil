"""Tests for the auth service.

Mocks the UserStore — no live database. Exercises:
- register creates tenant + user
- login succeeds with correct password, fails with wrong
- refresh rotates tokens (old becomes invalid)
- refresh fails on revoked token
- logout revokes the supplied refresh token
- invite creates user under same tenant
- password validation rules enforced
- expired access token rejected
- tampered token rejected
"""

from __future__ import annotations
import asyncio
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional
from uuid import UUID, uuid4

import jwt
import pytest
from fastapi.testclient import TestClient

# Set env BEFORE importing config so AUTH_SECRET takes effect.
os.environ["AUTH_SECRET"] = "test-secret-do-not-use-in-prod"
os.environ["DATABASE_URL"] = "postgresql://localhost/unused"
os.environ["ENVIRONMENT"] = "test"

from vigil_api import auth_routes
from vigil_api.config import reset_config_for_tests, get_config
from vigil_api.main import create_app
from vigil_api.password import hash_password, verify_password
from vigil_api.tokens import JWT_ALGORITHM, create_access_token
from vigil_api.user_store import RefreshTokenRow, UserRow, TenantRow


# ── fake store ──────────────────────────────────────────────────────────────

@dataclass
class FakeUser:
    user_id: UUID
    tenant_id: UUID
    email: str
    password_hash: str
    role: str
    is_active: bool = True
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_login: Optional[datetime] = None


@dataclass
class FakeRefresh:
    token_id: UUID
    user_id: UUID
    token_hash: str
    expires_at: datetime
    revoked: bool = False
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class FakePoolConn:
    """Mimics asyncpg connection just enough for the refresh route's raw query."""

    def __init__(self, store: "FakeUserStore"):
        self.store = store

    async def fetch(self, sql: str, *args):
        # Only one raw fetch path: list active refresh tokens (all users).
        active = []
        now = datetime.now(timezone.utc)
        for t in self.store._refresh.values():
            if not t.revoked and t.expires_at > now:
                active.append(
                    {
                        "token_id": t.token_id,
                        "token_hash": t.token_hash,
                        "user_id": t.user_id,
                    }
                )
        return active

    async def execute(self, sql: str, *args):
        if "SELECT 1" in sql:
            return None
        return None


class FakePool:
    def __init__(self, store: "FakeUserStore"):
        self.store = store

    def acquire(self):
        store = self.store

        class _Cm:
            async def __aenter__(self_inner):
                return FakePoolConn(store)

            async def __aexit__(self_inner, *exc):
                return False

        return _Cm()


class FakeUserStore:
    """Drop-in for UserStore. Holds in-memory tenants/users/tokens."""

    def __init__(self):
        self._tenants: dict[UUID, dict] = {}
        self._users: dict[UUID, FakeUser] = {}
        self._refresh: dict[UUID, FakeRefresh] = {}
        self.pool = FakePool(self)

    async def close(self):
        return None

    async def create_tenant_with_admin(self, *, tenant_name, email, password_hash):
        tenant_id = uuid4()
        self._tenants[tenant_id] = {
            "tenant_id": tenant_id,
            "name": tenant_name,
            "created_at": datetime.now(timezone.utc),
        }
        user = FakeUser(
            user_id=uuid4(),
            tenant_id=tenant_id,
            email=email,
            password_hash=password_hash,
            role="admin",
        )
        self._users[user.user_id] = user
        return (
            TenantRow(
                tenant_id=tenant_id,
                name=tenant_name,
                created_at=self._tenants[tenant_id]["created_at"],
            ),
            UserRow(
                user_id=user.user_id,
                tenant_id=user.tenant_id,
                email=user.email,
                password_hash=user.password_hash,
                role=user.role,
                is_active=user.is_active,
                created_at=user.created_at,
                last_login=user.last_login,
            ),
        )

    async def create_user(self, *, tenant_id, email, password_hash, role):
        user = FakeUser(
            user_id=uuid4(),
            tenant_id=tenant_id,
            email=email,
            password_hash=password_hash,
            role=role,
        )
        self._users[user.user_id] = user
        return UserRow(
            user_id=user.user_id,
            tenant_id=user.tenant_id,
            email=user.email,
            password_hash=user.password_hash,
            role=user.role,
            is_active=user.is_active,
            created_at=user.created_at,
            last_login=user.last_login,
        )

    async def get_user_by_email(self, email):
        for u in self._users.values():
            if u.email == email:
                return self._to_row(u)
        return None

    async def get_user_by_id(self, user_id: UUID):
        u = self._users.get(user_id)
        return self._to_row(u) if u else None

    async def update_last_login(self, user_id: UUID, when: datetime):
        u = self._users.get(user_id)
        if u:
            u.last_login = when

    async def create_refresh_token(self, *, user_id, token_hash, expires_at):
        rec = FakeRefresh(
            token_id=uuid4(),
            user_id=user_id,
            token_hash=token_hash,
            expires_at=expires_at,
        )
        self._refresh[rec.token_id] = rec
        return RefreshTokenRow(
            token_id=rec.token_id,
            user_id=rec.user_id,
            token_hash=rec.token_hash,
            expires_at=rec.expires_at,
            revoked=rec.revoked,
            created_at=rec.created_at,
        )

    async def list_active_refresh_tokens(self, user_id):
        now = datetime.now(timezone.utc)
        out = []
        for t in self._refresh.values():
            if t.user_id == user_id and not t.revoked and t.expires_at > now:
                out.append(
                    RefreshTokenRow(
                        token_id=t.token_id,
                        user_id=t.user_id,
                        token_hash=t.token_hash,
                        expires_at=t.expires_at,
                        revoked=t.revoked,
                        created_at=t.created_at,
                    )
                )
        return out

    async def revoke_refresh_token(self, token_id):
        if token_id in self._refresh:
            self._refresh[token_id].revoked = True

    @staticmethod
    def _to_row(u: FakeUser) -> UserRow:
        return UserRow(
            user_id=u.user_id,
            tenant_id=u.tenant_id,
            email=u.email,
            password_hash=u.password_hash,
            role=u.role,
            is_active=u.is_active,
            created_at=u.created_at,
            last_login=u.last_login,
        )


# ── fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture()
def fake_store():
    return FakeUserStore()


@pytest.fixture()
def client(fake_store):
    """TestClient that bypasses lifespan (which would touch a real DB)."""
    reset_config_for_tests()
    app = create_app()
    app.state.user_store = fake_store
    app.state.config = get_config()

    # The dependency reads request.app.state.user_store, so attaching is
    # sufficient — no override needed. Build the client without firing lifespan.
    with TestClient(app) as c:
        # TestClient context fires lifespan; we replace store again right after
        # because the lifespan would have nuked our fake when failing to connect.
        # Easier: skip lifespan entirely.
        yield c


# Strict client that does NOT enter lifespan (for tests that would otherwise
# fail because lifespan tries to create an asyncpg pool against an unused DSN).

@pytest.fixture()
def app_with_fake(fake_store):
    reset_config_for_tests()

    # Build an app without the lifespan attempting real DB connections.
    from fastapi import FastAPI
    from vigil_api.auth_routes import router as auth_router

    app = FastAPI()
    app.include_router(auth_router)
    app.state.user_store = fake_store
    return app


@pytest.fixture()
def tc(app_with_fake):
    with TestClient(app_with_fake) as c:
        yield c


# ── tests ───────────────────────────────────────────────────────────────────

VALID_PWD = "Sup3rS3cret!Pass"


def test_register_creates_tenant_and_user(tc, fake_store):
    res = tc.post(
        "/auth/register",
        json={"email": "alice@example.com", "password": VALID_PWD, "tenant_name": "Acme"},
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["access_token"]
    assert body["refresh_token"]
    assert body["user"]["email"] == "alice@example.com"
    assert body["user"]["role"] == "admin"
    assert len(fake_store._tenants) == 1
    assert len(fake_store._users) == 1


def test_register_password_validation(tc):
    bad = [
        "short",                      # too short
        "alllowercase1234567!",       # missing uppercase
        "NoNumberHere!Password",      # missing digit
        "NoSpecial1234567Abcdef",     # missing special
    ]
    for pw in bad:
        res = tc.post(
            "/auth/register",
            json={"email": f"bad+{pw}@x.com", "password": pw, "tenant_name": "X"},
        )
        assert res.status_code == 400, f"expected 400 for {pw!r}, got {res.status_code}"


def test_register_duplicate_email_rejected(tc):
    payload = {"email": "dup@example.com", "password": VALID_PWD, "tenant_name": "Acme"}
    assert tc.post("/auth/register", json=payload).status_code == 200
    assert tc.post("/auth/register", json=payload).status_code == 409


def test_login_succeeds_with_correct_password(tc):
    tc.post(
        "/auth/register",
        json={"email": "bob@example.com", "password": VALID_PWD, "tenant_name": "Acme"},
    )
    res = tc.post("/auth/login", json={"email": "bob@example.com", "password": VALID_PWD})
    assert res.status_code == 200
    assert res.json()["access_token"]


def test_login_fails_with_wrong_password(tc):
    tc.post(
        "/auth/register",
        json={"email": "carol@example.com", "password": VALID_PWD, "tenant_name": "Acme"},
    )
    res = tc.post("/auth/login", json={"email": "carol@example.com", "password": "Wr0ng!password"})
    assert res.status_code == 401


def test_login_fails_for_unknown_user(tc):
    res = tc.post("/auth/login", json={"email": "ghost@example.com", "password": VALID_PWD})
    assert res.status_code == 401


def test_refresh_rotates_tokens(tc):
    reg = tc.post(
        "/auth/register",
        json={"email": "dan@example.com", "password": VALID_PWD, "tenant_name": "Acme"},
    ).json()
    old_refresh = reg["refresh_token"]

    res = tc.post("/auth/refresh", json={"refresh_token": old_refresh})
    assert res.status_code == 200
    body = res.json()
    new_refresh = body["refresh_token"]
    assert new_refresh != old_refresh

    # Old token must now be invalid (revoked).
    second = tc.post("/auth/refresh", json={"refresh_token": old_refresh})
    assert second.status_code == 401


def test_refresh_fails_with_invalid_token(tc):
    res = tc.post("/auth/refresh", json={"refresh_token": "0" * 128})
    assert res.status_code == 401


def test_logout_revokes_token(tc):
    reg = tc.post(
        "/auth/register",
        json={"email": "eve@example.com", "password": VALID_PWD, "tenant_name": "Acme"},
    ).json()
    res = tc.post(
        "/auth/logout",
        json={"refresh_token": reg["refresh_token"]},
        headers={"Authorization": f"Bearer {reg['access_token']}"},
    )
    assert res.status_code == 200
    # Refresh with the revoked token must fail.
    res2 = tc.post("/auth/refresh", json={"refresh_token": reg["refresh_token"]})
    assert res2.status_code == 401


def test_logout_requires_access_token(tc):
    res = tc.post("/auth/logout", json={"refresh_token": "x" * 64})
    assert res.status_code == 401


def test_me_returns_user(tc):
    reg = tc.post(
        "/auth/register",
        json={"email": "frank@example.com", "password": VALID_PWD, "tenant_name": "Acme"},
    ).json()
    res = tc.get("/auth/me", headers={"Authorization": f"Bearer {reg['access_token']}"})
    assert res.status_code == 200
    body = res.json()
    assert body["email"] == "frank@example.com"
    assert body["role"] == "admin"


def test_invite_creates_user_under_same_tenant(tc, fake_store):
    reg = tc.post(
        "/auth/register",
        json={"email": "admin@example.com", "password": VALID_PWD, "tenant_name": "Acme"},
    ).json()
    admin_tenant = reg["user"]["tenant_id"]

    res = tc.post(
        "/auth/users/invite",
        json={"email": "newbie@example.com", "role": "analyst"},
        headers={"Authorization": f"Bearer {reg['access_token']}"},
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["email"] == "newbie@example.com"
    assert body["temporary_password"]

    # New user is in the same tenant.
    new_user = next(u for u in fake_store._users.values() if u.email == "newbie@example.com")
    assert str(new_user.tenant_id) == admin_tenant


def test_invite_requires_admin(tc, fake_store):
    reg = tc.post(
        "/auth/register",
        json={"email": "owner@example.com", "password": VALID_PWD, "tenant_name": "Acme"},
    ).json()
    # Demote to analyst.
    user = next(u for u in fake_store._users.values() if u.email == "owner@example.com")
    user.role = "analyst"

    res = tc.post(
        "/auth/users/invite",
        json={"email": "x@y.com", "role": "analyst"},
        headers={"Authorization": f"Bearer {reg['access_token']}"},
    )
    assert res.status_code == 403


def test_expired_access_token_rejected(tc):
    reg = tc.post(
        "/auth/register",
        json={"email": "exp@example.com", "password": VALID_PWD, "tenant_name": "Acme"},
    ).json()
    user_id = reg["user"]["user_id"]
    tenant_id = reg["user"]["tenant_id"]

    # Mint an already-expired token.
    cfg = get_config()
    expired = jwt.encode(
        {
            "sub": user_id,
            "tenant_id": tenant_id,
            "role": "admin",
            "email": "exp@example.com",
            "iat": int(time.time()) - 7200,
            "exp": int(time.time()) - 60,
        },
        cfg.auth_secret,
        algorithm=JWT_ALGORITHM,
    )
    res = tc.get("/auth/me", headers={"Authorization": f"Bearer {expired}"})
    assert res.status_code == 401


def test_tampered_token_rejected(tc):
    cfg = get_config()
    token = jwt.encode(
        {
            "sub": str(uuid4()),
            "tenant_id": str(uuid4()),
            "role": "admin",
            "email": "x@y.com",
            "iat": int(time.time()),
            "exp": int(time.time()) + 600,
        },
        "wrong-secret",
        algorithm=JWT_ALGORITHM,
    )
    res = tc.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 401


def test_password_hash_uses_bcrypt_with_cost_12():
    h = hash_password("Sup3rS3cret!Pass")
    # passlib bcrypt format: $2b$12$...
    assert h.startswith("$2b$12$") or h.startswith("$2a$12$"), f"unexpected hash: {h[:7]}"
    assert verify_password("Sup3rS3cret!Pass", h)
    assert not verify_password("wrong", h)
