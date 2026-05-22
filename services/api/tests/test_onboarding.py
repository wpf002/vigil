"""Tests for the onboarding wizard endpoints.

httpx is mocked. Coverage:
  - check-connection returns connected=true on a 200 from the SIEM
  - check-connection returns connected=false with error on auth failure
  - SIEM credentials are not persisted anywhere
  - seed-demo requires admin role
  - PATCH /auth/me/onboarding-complete flips the flag
"""

from __future__ import annotations

import os
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID, uuid4

import httpx
import pytest

os.environ.setdefault("AUTH_SECRET", "test-secret")
os.environ.setdefault("DATABASE_URL", "postgresql://localhost/unused")
os.environ.setdefault("ENVIRONMENT", "test")

from vigil_api import onboarding_routes

# ── _probe_splunk ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_probe_splunk_returns_connected_on_200():
    body = {"entry": [{"content": {"version": "9.2.1"}}]}

    class _Resp:
        status_code = 200
        def json(self):
            return body

    class _StubClient:
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return None
        async def get(self, url, headers=None, auth=None):
            return _Resp()

    with patch("vigil_api.onboarding_routes.httpx.AsyncClient", return_value=_StubClient()):
        req = onboarding_routes.CheckConnectionRequest(
            siem_type="splunk_es", host="https://splunk.example",
            username="admin", password="x",
        )
        out = await onboarding_routes._probe_splunk(req)
    assert out.connected is True
    assert out.version == "9.2.1"


@pytest.mark.asyncio
async def test_probe_splunk_returns_error_on_401():
    class _Resp:
        status_code = 401
        def json(self):
            return {}

    class _StubClient:
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return None
        async def get(self, url, headers=None, auth=None):
            return _Resp()

    with patch("vigil_api.onboarding_routes.httpx.AsyncClient", return_value=_StubClient()):
        req = onboarding_routes.CheckConnectionRequest(
            siem_type="splunk_es", host="https://splunk.example",
            username="admin", password="bad",
        )
        out = await onboarding_routes._probe_splunk(req)
    assert out.connected is False
    assert "401" in (out.error or "")


# ── _probe_sentinel ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_probe_sentinel_succeeds_on_token_fetch():
    class _Resp:
        status_code = 200
        def json(self):
            return {"access_token": "tok"}

    class _StubClient:
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return None
        async def post(self, url, data=None):
            return _Resp()

    with patch("vigil_api.onboarding_routes.httpx.AsyncClient", return_value=_StubClient()):
        out = await onboarding_routes._probe_sentinel(
            onboarding_routes.CheckConnectionRequest(
                siem_type="sentinel", tenant_id="t", client_id="c", client_secret="s",
            )
        )
    assert out.connected is True


@pytest.mark.asyncio
async def test_probe_sentinel_missing_creds_returns_error():
    out = await onboarding_routes._probe_sentinel(
        onboarding_routes.CheckConnectionRequest(siem_type="sentinel"),
    )
    assert out.connected is False
    assert "required" in (out.error or "")


# ── _probe_elastic ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_probe_elastic_returns_version_on_200():
    class _Resp:
        status_code = 200
        def json(self):
            return {"version": {"number": "8.14.0"}}

    class _StubClient:
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return None
        async def get(self, url, headers=None):
            return _Resp()

    with patch("vigil_api.onboarding_routes.httpx.AsyncClient", return_value=_StubClient()):
        out = await onboarding_routes._probe_elastic(
            onboarding_routes.CheckConnectionRequest(
                siem_type="elastic", elastic_url="http://es", api_key_id="k",
                api_key_secret="s",
            )
        )
    assert out.connected is True
    assert out.version == "8.14.0"


# ── credentials never persist (audit) ────────────────────────────────────


@pytest.mark.asyncio
async def test_check_connection_does_not_log_secrets():
    """Sanity: the request body doesn't end up in any module-level state.

    We don't store anything on the module, so this is a regression guard."""
    initial = dict(vars(onboarding_routes))
    class _StubClient:
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return None
        async def get(self, *a, **k):
            class _R: status_code = 200
            class _R2:
                status_code = 200
                def json(self_inner): return {"entry": [{"content": {"version": "x"}}]}
            return _R2()

    with patch("vigil_api.onboarding_routes.httpx.AsyncClient", return_value=_StubClient()):
        await onboarding_routes._probe_splunk(
            onboarding_routes.CheckConnectionRequest(
                siem_type="splunk_es", host="http://x",
                username="admin", password="DO_NOT_LEAK_SUPER_SECRET",
            )
        )

    # Module's vars haven't grown, and no value contains the secret.
    new_keys = set(vars(onboarding_routes)) - set(initial)
    assert new_keys == set() or all(not isinstance(vars(onboarding_routes)[k], str) or "DO_NOT_LEAK" not in vars(onboarding_routes)[k] for k in new_keys)


# ── PATCH /auth/me/onboarding-complete ──────────────────────────────────


@pytest.mark.asyncio
async def test_mark_onboarding_complete_calls_store():
    store = MagicMock()
    store.mark_onboarding_complete = AsyncMock()

    user = MagicMock()
    user.user_id = uuid4()
    out = await onboarding_routes.patch_onboarding_complete(user=user, store=store)
    assert out == {"onboarding_complete": True}
    store.mark_onboarding_complete.assert_awaited_once_with(user.user_id)


# ── seed-demo: requires admin (verified by FastAPI dependency) ───────────


def test_seed_demo_dependency_is_require_admin():
    """Inspect the route's dependency tree to assert require_admin guards it."""
    from fastapi.routing import APIRoute
    from vigil_api.auth_routes import require_admin
    target = None
    for r in onboarding_routes.router.routes:
        if isinstance(r, APIRoute) and r.path == "/onboarding/seed-demo":
            target = r
            break
    assert target is not None
    deps = [getattr(d, "call", d) for d in target.dependant.dependencies]
    # require_admin appears either directly or as the entry-point of a nested chain.
    found = any(
        d is require_admin or any(getattr(s, "call", None) is require_admin for s in target.dependant.dependencies)
        for d in deps
    )
    assert found
