"""Tests for the SOAR clients and the dispatcher.

httpx is mocked — no live SOAR calls. Coverage:
  - XSOAR client sends correct headers, body shape per action
  - XSOAR client retries on 5xx, raises on 4xx without retry
  - XSOAR client raises after max retries
  - Tines client posts to the correct webhook URL per action
  - Tines client raises when no URL configured for an action
  - Stub mode is unchanged (default)
  - Dispatcher honours SOAR_BACKEND env var
"""

from __future__ import annotations
import os
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from playbook_engine.soar.tines import TinesClient, TinesError
from playbook_engine.soar.xsoar import XSOARClient, XSOARError


# ── XSOAR ────────────────────────────────────────────────────────────────


class _FakeResp:
    def __init__(self, status_code: int, body: dict | None = None, text: str = ""):
        self.status_code = status_code
        self._body = body or {}
        self.text = text or str(body)

    def json(self) -> dict[str, Any]:
        return self._body


class _StubAsyncClient:
    """httpx.AsyncClient stand-in that records requests and returns a script."""

    def __init__(self, responses: list[_FakeResp]):
        self.responses = responses
        self.calls: list[dict[str, Any]] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return None

    async def post(self, url: str, headers: dict | None = None, json: dict | None = None):
        self.calls.append({"url": url, "headers": headers or {}, "json": json or {}})
        if not self.responses:
            return _FakeResp(200, {"id": "fallback"})
        return self.responses.pop(0)


def _patch_xsoar(client: _StubAsyncClient):
    return patch("playbook_engine.soar.xsoar.httpx.AsyncClient", return_value=client)


@pytest.mark.asyncio
async def test_xsoar_isolate_host_sends_correct_body():
    stub = _StubAsyncClient([_FakeResp(200, {"id": "inc-1"})])
    with _patch_xsoar(stub):
        c = XSOARClient(base_url="https://xsoar.example", api_key="api-key-x")
        out = await c.isolate_host("dc01", tenant_id="t-1", attack_id="a-1")
    assert out == {"success": True, "backend": "xsoar", "reference_id": "inc-1"}
    assert len(stub.calls) == 1
    call = stub.calls[0]
    assert call["url"] == "https://xsoar.example/incident"
    assert call["headers"]["Authorization"] == "api-key-x"
    assert call["json"]["type"] == "VIGIL - Isolate Host"
    assert call["json"]["name"] == "Isolate dc01"
    assert "dc01" in call["json"]["details"]


@pytest.mark.asyncio
async def test_xsoar_action_types_each_distinct():
    stub = _StubAsyncClient([_FakeResp(200, {"id": "x"}) for _ in range(6)])
    with _patch_xsoar(stub):
        c = XSOARClient(base_url="https://xsoar.example", api_key="k")
        await c.isolate_host("h", "t", "a")
        await c.kill_process("proc.exe", "h", "t", "a")
        await c.reset_credentials("alice", "t", "a")
        await c.capture_forensic_snapshot("h", "t", "a")
        await c.block_protocol("SMB", "h", "t", "a")
        await c.review_auth_logs("h", "t", "a")

    types = [call["json"]["type"] for call in stub.calls]
    assert types == [
        "VIGIL - Isolate Host",
        "VIGIL - Kill Process",
        "VIGIL - Reset Credentials",
        "VIGIL - Capture Forensic Snapshot",
        "VIGIL - Block Protocol",
        "VIGIL - Review Auth Logs",
    ]


@pytest.mark.asyncio
async def test_xsoar_retries_on_5xx():
    stub = _StubAsyncClient([
        _FakeResp(500, text="boom"),
        _FakeResp(502, text="bad gateway"),
        _FakeResp(200, {"id": "inc-99"}),
    ])
    with _patch_xsoar(stub):
        c = XSOARClient(base_url="https://x.example", api_key="k")
        out = await c.isolate_host("h", "t", "a")
    assert out["reference_id"] == "inc-99"
    assert len(stub.calls) == 3


@pytest.mark.asyncio
async def test_xsoar_no_retry_on_4xx():
    stub = _StubAsyncClient([_FakeResp(400, text="bad request")])
    with _patch_xsoar(stub):
        c = XSOARClient(base_url="https://x.example", api_key="k")
        with pytest.raises(XSOARError):
            await c.isolate_host("h", "t", "a")
    assert len(stub.calls) == 1


@pytest.mark.asyncio
async def test_xsoar_gives_up_after_max_retries():
    stub = _StubAsyncClient([_FakeResp(500, text="b") for _ in range(5)])
    with _patch_xsoar(stub):
        c = XSOARClient(base_url="https://x.example", api_key="k")
        with pytest.raises(XSOARError):
            await c.isolate_host("h", "t", "a")
    # tenacity retries 3 times total.
    assert len(stub.calls) == 3


# ── Tines ────────────────────────────────────────────────────────────────


def _patch_tines(client: _StubAsyncClient):
    return patch("playbook_engine.soar.tines.httpx.AsyncClient", return_value=client)


@pytest.mark.asyncio
async def test_tines_posts_to_correct_webhook_per_action():
    stub = _StubAsyncClient([_FakeResp(200, {"id": "ok"}) for _ in range(2)])
    webhooks = {
        "isolate_host":      "https://tines.example/whk-iso",
        "reset_credentials": "https://tines.example/whk-rst",
    }
    with _patch_tines(stub):
        c = TinesClient(api_key="t-key", webhooks=webhooks)
        await c.isolate_host("h", "t", "a")
        await c.reset_credentials("alice", "t", "a")
    assert stub.calls[0]["url"] == "https://tines.example/whk-iso"
    assert stub.calls[1]["url"] == "https://tines.example/whk-rst"
    # Bearer token applied.
    assert stub.calls[0]["headers"]["Authorization"] == "Bearer t-key"
    # Body fields present.
    assert stub.calls[0]["json"]["action"] == "isolate_host"
    assert stub.calls[0]["json"]["target"] == "h"
    assert stub.calls[0]["json"]["tenant_id"] == "t"
    assert stub.calls[0]["json"]["attack_id"] == "a"
    assert "timestamp" in stub.calls[0]["json"]


@pytest.mark.asyncio
async def test_tines_raises_when_action_not_configured():
    stub = _StubAsyncClient([])
    with _patch_tines(stub):
        c = TinesClient(api_key="k", webhooks={})
        with pytest.raises(TinesError):
            await c.isolate_host("h", "t", "a")
    assert stub.calls == []


# ── stub mode + dispatcher ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_stub_mode_returns_success_without_http():
    """SOAR_BACKEND defaults to stub. Calling the underlying _dispatch via
    the activity body should not touch httpx."""
    from playbook_engine.activities.response_activities import _dispatch

    os.environ.pop("SOAR_BACKEND", None)
    res = await _dispatch("isolate_host", host="h", tenant_id="t", attack_id="a")
    assert res == {"success": True, "backend": "stub", "reference_id": None}


@pytest.mark.asyncio
async def test_dispatcher_routes_to_xsoar():
    from playbook_engine.activities import response_activities as ra

    os.environ["SOAR_BACKEND"] = "xsoar"
    os.environ["XSOAR_BASE_URL"] = "https://x.example"
    os.environ["XSOAR_API_KEY"] = "k"

    stub = _StubAsyncClient([_FakeResp(200, {"id": "inc-1"})])
    try:
        with patch("playbook_engine.soar.xsoar.httpx.AsyncClient", return_value=stub):
            res = await ra._dispatch("isolate_host", host="h", tenant_id="t", attack_id="a")
        assert res["backend"] == "xsoar"
        assert res["reference_id"] == "inc-1"
    finally:
        os.environ.pop("SOAR_BACKEND", None)
        os.environ.pop("XSOAR_BASE_URL", None)
        os.environ.pop("XSOAR_API_KEY", None)


@pytest.mark.asyncio
async def test_dispatcher_routes_to_tines():
    from playbook_engine.activities import response_activities as ra

    os.environ["SOAR_BACKEND"] = "tines"
    os.environ["TINES_WEBHOOK_ISOLATE_HOST"] = "https://tines.example/whk"
    os.environ["TINES_API_KEY"] = "tk"

    stub = _StubAsyncClient([_FakeResp(200, {"id": "ok"})])
    try:
        with patch("playbook_engine.soar.tines.httpx.AsyncClient", return_value=stub):
            res = await ra._dispatch("isolate_host", host="h", tenant_id="t", attack_id="a")
        assert res["backend"] == "tines"
    finally:
        for k in ("SOAR_BACKEND", "TINES_WEBHOOK_ISOLATE_HOST", "TINES_API_KEY"):
            os.environ.pop(k, None)
