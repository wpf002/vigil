"""Tests for the Microsoft Sentinel connector — httpx is mocked."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from ..connectors.sentinel import (
    SentinelAPIError,
    SentinelAuthError,
    SentinelConnector,
)
from ..models.cdm import Severity


def _make_connector(redis_client=None) -> SentinelConnector:
    return SentinelConnector(
        tenant_id="tenant-aaaa",
        client_id="client-bbbb",
        client_secret="secret-cccc",
        subscription_id="sub-dddd",
        resource_group="rg-eeee",
        workspace_name="ws-ffff",
        redis_client=redis_client,
    )


class _FakeResp:
    def __init__(self, status_code: int, body: dict[str, Any] | None = None, text: str = ""):
        self.status_code = status_code
        self._body = body or {}
        self.text = text or str(body)

    def json(self) -> dict[str, Any]:
        return self._body

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            import httpx
            req = httpx.Request("POST", "http://example")
            raise httpx.HTTPStatusError(
                f"{self.status_code}", request=req,
                response=httpx.Response(self.status_code, request=req),
            )


@pytest.mark.asyncio
async def test_fetch_token_caches_in_redis():
    redis = MagicMock()
    redis.get = AsyncMock(return_value=None)
    redis.setex = AsyncMock(return_value=True)

    c = _make_connector(redis_client=redis)
    c._client = MagicMock()
    c._client.post = AsyncMock(
        return_value=_FakeResp(200, {"access_token": "tok-1", "expires_in": 3600})
    )

    token = await c._get_token()
    assert token == "tok-1"
    # TTL should be expires_in - 60.
    setex_args = redis.setex.await_args
    assert setex_args.args[0] == "sentinel:token:tenant-aaaa"
    assert setex_args.args[1] == 3540
    assert setex_args.args[2] == "tok-1"


@pytest.mark.asyncio
async def test_token_reused_from_redis_when_present():
    redis = MagicMock()
    redis.get = AsyncMock(return_value=b"cached-tok")
    c = _make_connector(redis_client=redis)
    c._client = MagicMock()
    c._client.post = AsyncMock()  # would explode if called

    token = await c._get_token()
    assert token == "cached-tok"
    c._client.post.assert_not_awaited()


@pytest.mark.asyncio
async def test_refresh_on_401_retries_with_new_token():
    c = _make_connector()
    c._client = MagicMock()

    # First _get_token call: fetch new token.
    c._client.post = AsyncMock(
        return_value=_FakeResp(200, {"access_token": "tok-1", "expires_in": 3600})
    )

    # Build a request side_effect: 401 first, 200 next.
    responses = [
        _FakeResp(401, {"error": "expired"}),
        _FakeResp(
            200,
            {"value": [{"name": "inc-1", "properties": {
                "title": "Brute force", "severity": "High",
                "createdTimeUtc": "2026-05-08T01:02:03Z", "status": "New"}}]},
        ),
    ]
    c._client.request = AsyncMock(side_effect=responses)

    incidents = await c.get_incidents()
    assert c._client.request.await_count == 2
    # Each retry uses a fresh token — request was called with Authorization header twice.
    headers_first = c._client.request.await_args_list[0].kwargs["headers"]
    headers_second = c._client.request.await_args_list[1].kwargs["headers"]
    assert headers_first["Authorization"].startswith("Bearer ")
    assert headers_second["Authorization"].startswith("Bearer ")
    assert len(incidents) == 1


@pytest.mark.asyncio
async def test_get_incidents_paginates_via_next_link():
    c = _make_connector()
    c._client = MagicMock()
    c._token = "stub"
    c._token_expires_at = datetime.now(timezone.utc).timestamp() + 600

    page1 = _FakeResp(200, {
        "value": [{"name": "inc-1", "properties": {"title": "a", "severity": "Low",
                  "createdTimeUtc": "2026-05-08T01:00:00Z"}}],
        "nextLink": "https://management.azure.com/next-page",
    })
    page2 = _FakeResp(200, {
        "value": [{"name": "inc-2", "properties": {"title": "b", "severity": "Medium",
                  "createdTimeUtc": "2026-05-08T01:10:00Z"}}],
    })
    c._client.request = AsyncMock(side_effect=[page1, page2])
    incidents = await c.get_incidents()
    assert [i["name"] for i in incidents] == ["inc-1", "inc-2"]
    assert c._client.request.await_count == 2


def test_map_incident_to_cdm_event_basic():
    c = _make_connector()
    incident = {
        "id": "/subs/x/incidents/inc-1",
        "name": "inc-1",
        "properties": {
            "title": "Suspicious sign-in",
            "severity": "High",
            "status": "New",
            "createdTimeUtc": "2026-05-08T01:02:03Z",
            "incidentNumber": 42,
            "alertProductNames": ["Microsoft Defender"],
            "additionalData": {"tactics": ["CredentialAccess"]},
        },
    }
    cdm = c.map_incident(incident, tenant_id="t-1")
    assert cdm.tenant_id == "t-1"
    assert cdm.source_event_id == "inc-1"
    assert cdm.source_siem == "sentinel"
    assert cdm.severity == Severity.HIGH
    assert cdm.title == "Suspicious sign-in"
    assert cdm.rule_name == "Microsoft Defender"
    assert cdm.rule_id == "42"
    assert cdm.mitre is not None
    assert cdm.mitre.tactic == "CredentialAccess"
    # Raw event preserved.
    assert cdm.raw_event["name"] == "inc-1"


def test_map_incident_handles_severity_variants():
    c = _make_connector()
    cases = [
        ("High", Severity.HIGH),
        ("Medium", Severity.MEDIUM),
        ("Low", Severity.LOW),
        ("Informational", Severity.INFO),
        ("garbage", Severity.UNKNOWN),
        (None, Severity.UNKNOWN),
    ]
    for raw, expected in cases:
        ev = c.map_incident(
            {"name": "x", "properties": {"title": "t", "severity": raw,
             "createdTimeUtc": "2026-05-08T00:00:00Z"}},
            tenant_id="t",
        )
        assert ev.severity == expected, raw


@pytest.mark.asyncio
async def test_token_fetch_raises_on_aad_error():
    c = _make_connector()
    c._client = MagicMock()
    c._client.post = AsyncMock(return_value=_FakeResp(401, {"error": "invalid_client"}))
    with pytest.raises(SentinelAuthError):
        await c._fetch_token()


@pytest.mark.asyncio
async def test_get_incidents_raises_on_500():
    c = _make_connector()
    c._client = MagicMock()
    c._token = "stub"
    c._token_expires_at = datetime.now(timezone.utc).timestamp() + 600
    c._client.request = AsyncMock(return_value=_FakeResp(500, {"error": "boom"}, text="boom"))
    with pytest.raises(SentinelAPIError):
        await c.get_incidents()
