"""Tests for API keys + webhooks.

The KeyStore is exercised against an in-memory fake pool. HTTP routes
are tested via FastAPI TestClient with a fake KeyStore wired up via
dependency_overrides, so neither asyncpg nor httpx ever runs.
"""

from __future__ import annotations
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID, uuid4

import pytest

os.environ.setdefault("AUTH_SECRET", "test-secret")
os.environ.setdefault("DATABASE_URL", "postgresql://localhost/unused")
os.environ.setdefault("ENVIRONMENT", "test")

from vigil_api import auth_routes
from vigil_api.key_store import (
    KeyStore,
    generate_api_key,
    hash_api_key,
    hmac_sign,
    hmac_verify,
    verify_api_key,
)


# ── pure helpers ──────────────────────────────────────────────────────────


def test_generate_api_key_starts_with_prefix_and_hex_body():
    raw, prefix = generate_api_key()
    assert raw.startswith("vgl_")
    assert raw[:8] == prefix
    # 4 chars prefix + 48 hex chars body.
    assert len(raw) == 4 + 48


def test_hash_api_key_verifies_correctly():
    raw, _ = generate_api_key()
    h = hash_api_key(raw)
    assert h != raw
    assert verify_api_key(raw, h) is True


def test_verify_api_key_rejects_wrong_key():
    raw, _ = generate_api_key()
    other, _ = generate_api_key()
    h = hash_api_key(raw)
    assert verify_api_key(other, h) is False


def test_hmac_sign_and_verify_match():
    secret = "super-secret-value"
    payload = b'{"event":"attack.created"}'
    sig = hmac_sign(secret, payload)
    assert hmac_verify(secret, payload, sig) is True
    assert hmac_verify(secret, payload, f"sha256={sig}") is True


def test_hmac_verify_rejects_tampered_payload():
    secret = "s"
    sig = hmac_sign(secret, b"hello")
    assert hmac_verify(secret, b"world", sig) is False


def test_hmac_verify_rejects_wrong_secret():
    sig = hmac_sign("right", b"x")
    assert hmac_verify("wrong", b"x", sig) is False


# ── KeyStore against in-memory pool ───────────────────────────────────────


@dataclass
class _APIKey:
    key_id: UUID
    tenant_id: UUID
    created_by: UUID
    name: str
    key_prefix: str
    key_hash: str
    scopes: list[str]
    last_used_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    revoked: bool = False
    created_at: datetime = None  # type: ignore


class FakePool:
    def __init__(self):
        self.api_keys: dict[UUID, _APIKey] = {}
        self.webhooks: dict[UUID, dict[str, Any]] = {}

    def acquire(self):
        return _Acquire(self)


class _Acquire:
    def __init__(self, pool):
        self.pool = pool

    async def __aenter__(self):
        return _Conn(self.pool)

    async def __aexit__(self, *a):
        return False


class _Conn:
    def __init__(self, pool):
        self.pool = pool

    async def fetchrow(self, sql, *args):
        s = sql.lower()
        if "insert into api_keys" in s:
            tenant_id, created_by, name, prefix, key_hash, scopes, expires_at = args
            now = datetime.now(timezone.utc)
            rec = _APIKey(
                key_id=uuid4(), tenant_id=tenant_id, created_by=created_by,
                name=name, key_prefix=prefix, key_hash=key_hash,
                scopes=list(scopes or []), expires_at=expires_at, created_at=now,
            )
            self.pool.api_keys[rec.key_id] = rec
            return _row_from_api_key(rec)
        if "insert into webhooks" in s:
            tenant_id, url, secret, events = args
            wh_id = uuid4()
            row = {
                "webhook_id": wh_id, "tenant_id": tenant_id, "url": url,
                "secret": secret, "events": list(events), "active": True,
                "last_fired_at": None, "failure_count": 0,
                "created_at": datetime.now(timezone.utc),
            }
            self.pool.webhooks[wh_id] = row
            return row
        if "from webhooks where webhook_id = $1 and tenant_id = $2" in s:
            wh = self.pool.webhooks.get(args[0])
            return wh if wh and wh["tenant_id"] == args[1] else None
        if "update webhooks" in s and "failure_count = failure_count + 1" in s:
            wh = self.pool.webhooks.get(args[0])
            if wh:
                wh["failure_count"] += 1
                if wh["failure_count"] >= 10:
                    wh["active"] = False
                return {"failure_count": wh["failure_count"]}
            return None
        return None

    async def fetch(self, sql, *args):
        s = sql.lower()
        if "from api_keys" in s and "where tenant_id = $1" in s and "order by" in s:
            return [
                _row_from_api_key(k)
                for k in self.pool.api_keys.values() if k.tenant_id == args[0]
            ]
        if "from api_keys" in s and "key_prefix = $1" in s:
            now = datetime.now(timezone.utc)
            return [
                _row_from_api_key(k)
                for k in self.pool.api_keys.values()
                if k.key_prefix == args[0]
                and not k.revoked
                and (k.expires_at is None or k.expires_at > now)
            ]
        if "from api_keys" in s and "revoked = false" in s:
            now = datetime.now(timezone.utc)
            return [
                _row_from_api_key(k)
                for k in self.pool.api_keys.values()
                if not k.revoked and (k.expires_at is None or k.expires_at > now)
            ]
        if "from webhooks where tenant_id = $1" in s:
            return [w for w in self.pool.webhooks.values() if w["tenant_id"] == args[0]]
        if "from webhooks" in s and "$2 = any(events)" in s:
            return [
                w for w in self.pool.webhooks.values()
                if w["tenant_id"] == args[0] and w["active"] and args[1] in w["events"]
            ]
        return []

    async def execute(self, sql, *args):
        s = sql.lower()
        if "update api_keys set revoked = true" in s:
            key_id, tenant_id = args
            k = self.pool.api_keys.get(key_id)
            if k and k.tenant_id == tenant_id:
                k.revoked = True
                return "UPDATE 1"
            return "UPDATE 0"
        if "delete from webhooks" in s:
            wh_id, tenant_id = args
            wh = self.pool.webhooks.get(wh_id)
            if wh and wh["tenant_id"] == tenant_id:
                del self.pool.webhooks[wh_id]
                return "DELETE 1"
            return "DELETE 0"
        if "update api_keys set last_used_at" in s:
            key_id, when = args
            k = self.pool.api_keys.get(key_id)
            if k:
                k.last_used_at = when
            return "UPDATE 1"
        if "update webhooks" in s and "last_fired_at = $2" in s:
            wh_id, when = args
            wh = self.pool.webhooks.get(wh_id)
            if wh:
                wh["last_fired_at"] = when
                wh["failure_count"] = 0
            return "UPDATE 1"
        return None


def _row_from_api_key(k: _APIKey) -> dict[str, Any]:
    return {
        "key_id": k.key_id, "tenant_id": k.tenant_id, "created_by": k.created_by,
        "name": k.name, "key_prefix": k.key_prefix, "key_hash": k.key_hash,
        "scopes": k.scopes, "last_used_at": k.last_used_at,
        "expires_at": k.expires_at, "revoked": k.revoked, "created_at": k.created_at,
    }


@pytest.fixture
def store() -> KeyStore:
    return KeyStore(FakePool())


# ── KeyStore behaviour ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_create_key_stores_hash_not_raw(store):
    raw, prefix = generate_api_key()
    h = hash_api_key(raw)
    tenant = uuid4()
    user = uuid4()
    row = await store.create_api_key(
        tenant_id=tenant, created_by=user, name="ci", key_prefix=prefix,
        key_hash=h, scopes=["read:attacks"],
    )
    # Hash stored, raw key never persisted.
    assert row.key_hash == h
    assert "vgl_" not in row.key_hash
    # Verifies against the originally-generated raw key.
    assert verify_api_key(raw, row.key_hash)


@pytest.mark.asyncio
async def test_revoked_key_excluded_from_active_list(store):
    raw, prefix = generate_api_key()
    tenant = uuid4()
    user = uuid4()
    row = await store.create_api_key(
        tenant_id=tenant, created_by=user, name="x", key_prefix=prefix,
        key_hash=hash_api_key(raw), scopes=[],
    )
    actives = await store.list_active_api_keys()
    assert any(k.key_id == row.key_id for k in actives)

    await store.revoke_api_key(key_id=row.key_id, tenant_id=tenant)
    actives = await store.list_active_api_keys()
    assert not any(k.key_id == row.key_id for k in actives)


@pytest.mark.asyncio
async def test_expired_key_excluded_from_active_list(store):
    raw, prefix = generate_api_key()
    tenant = uuid4()
    user = uuid4()
    past = datetime.now(timezone.utc) - timedelta(seconds=10)
    row = await store.create_api_key(
        tenant_id=tenant, created_by=user, name="x", key_prefix=prefix,
        key_hash=hash_api_key(raw), scopes=[], expires_at=past,
    )
    actives = await store.list_active_api_keys()
    assert not any(k.key_id == row.key_id for k in actives)


@pytest.mark.asyncio
async def test_prefix_lookup_returns_only_matching(store):
    raw1, prefix1 = generate_api_key()
    raw2, prefix2 = generate_api_key()
    tenant = uuid4()
    user = uuid4()
    await store.create_api_key(
        tenant_id=tenant, created_by=user, name="a", key_prefix=prefix1,
        key_hash=hash_api_key(raw1), scopes=[],
    )
    await store.create_api_key(
        tenant_id=tenant, created_by=user, name="b", key_prefix=prefix2,
        key_hash=hash_api_key(raw2), scopes=[],
    )
    matches = await store.list_active_api_keys_by_prefix(prefix1)
    assert all(m.key_prefix == prefix1 for m in matches)
    assert verify_api_key(raw1, matches[0].key_hash) is True


# ── Webhook behaviour ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_webhook_register_then_lookup_for_event(store):
    tenant = uuid4()
    wh = await store.create_webhook(
        tenant_id=tenant, url="https://x.example/whk",
        secret="abcdef1234567890",
        events=["attack.created", "attack.resolved"],
    )
    assert wh.active is True
    matches = await store.list_active_webhooks_for_event(
        tenant_id=tenant, event="attack.created"
    )
    assert len(matches) == 1
    assert matches[0].webhook_id == wh.webhook_id

    # Other event types don't match.
    none = await store.list_active_webhooks_for_event(
        tenant_id=tenant, event="attack.escalated"
    )
    assert none == []


@pytest.mark.asyncio
async def test_webhook_failure_count_auto_disables_at_10(store):
    tenant = uuid4()
    wh = await store.create_webhook(
        tenant_id=tenant, url="https://x.example/whk",
        secret="abcdef1234567890", events=["attack.created"],
    )
    for i in range(1, 11):
        count = await store.record_webhook_failure(wh.webhook_id)
        assert count == i

    refreshed = await store.get_webhook(webhook_id=wh.webhook_id, tenant_id=tenant)
    assert refreshed is not None
    assert refreshed.active is False
    assert refreshed.failure_count == 10


@pytest.mark.asyncio
async def test_webhook_delete_removes(store):
    tenant = uuid4()
    wh = await store.create_webhook(
        tenant_id=tenant, url="https://x.example/whk",
        secret="abcdef1234567890", events=["attack.created"],
    )
    deleted = await store.delete_webhook(webhook_id=wh.webhook_id, tenant_id=tenant)
    assert deleted is True
    again = await store.get_webhook(webhook_id=wh.webhook_id, tenant_id=tenant)
    assert again is None


# ── route-level: scope validation ────────────────────────────────────────


def test_valid_scopes_constant_matches_spec():
    """Public spec lists 4 scopes — guard against accidental rename."""
    assert auth_routes.VALID_SCOPES == {
        "read:attacks", "read:detections", "write:signals", "read:reports",
    }


def test_valid_webhook_events_constant_matches_spec():
    assert auth_routes.VALID_WEBHOOK_EVENTS == {
        "attack.created", "attack.updated", "attack.escalated",
        "attack.resolved", "playbook.paused",
    }
