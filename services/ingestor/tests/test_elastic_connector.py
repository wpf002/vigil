"""Tests for the Elastic connector — httpx is mocked."""

from __future__ import annotations

import base64
from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from ..connectors.elastic import ElasticAPIError, ElasticAuthError, ElasticConnector
from ..models.cdm import Severity


def _make_connector() -> ElasticConnector:
    return ElasticConnector(
        url="https://elastic.example:9200",
        api_key_id="kid",
        api_key_secret="ksec",
    )


class _FakeResp:
    def __init__(self, status_code: int, body: dict[str, Any] | None = None, text: str = ""):
        self.status_code = status_code
        self._body = body or {}
        self.text = text or str(body)

    def json(self) -> dict[str, Any]:
        return self._body


def test_auth_header_is_base64_apikey():
    c = _make_connector()
    expected = base64.b64encode(b"kid:ksec").decode("ascii")
    assert c.auth_header == f"ApiKey {expected}"


@pytest.mark.asyncio
async def test_get_active_alerts_builds_correct_query():
    c = _make_connector()
    c._client = MagicMock()
    c._client.post = AsyncMock(return_value=_FakeResp(200, {"hits": {"hits": []}}))

    since = datetime(2026, 5, 8, 1, 0, 0, tzinfo=timezone.utc)
    await c.get_active_alerts(since=since)

    args, kwargs = c._client.post.await_args
    url = args[0]
    body = kwargs["json"]
    assert url == "https://elastic.example:9200/.alerts-security.alerts-default/_search"
    must = body["query"]["bool"]["must"]
    # Active filter present.
    assert {"term": {"kibana.alert.status": "active"}} in must
    # Since converted to ISO.
    range_clause = next(m for m in must if "range" in m)
    assert range_clause["range"]["@timestamp"]["gte"] == "2026-05-08T01:00:00Z"
    assert body["size"] == 500


@pytest.mark.asyncio
async def test_get_active_alerts_default_since_uses_now_minus_15m():
    c = _make_connector()
    c._client = MagicMock()
    c._client.post = AsyncMock(return_value=_FakeResp(200, {"hits": {"hits": []}}))
    await c.get_active_alerts()
    body = c._client.post.await_args.kwargs["json"]
    range_clause = next(m for m in body["query"]["bool"]["must"] if "range" in m)
    assert range_clause["range"]["@timestamp"]["gte"] == "now-15m"


@pytest.mark.asyncio
async def test_get_active_alerts_raises_on_401():
    c = _make_connector()
    c._client = MagicMock()
    c._client.post = AsyncMock(return_value=_FakeResp(401, {"error": "invalid"}))
    with pytest.raises(ElasticAuthError):
        await c.get_active_alerts()


@pytest.mark.asyncio
async def test_get_active_alerts_raises_on_500():
    c = _make_connector()
    c._client = MagicMock()
    c._client.post = AsyncMock(return_value=_FakeResp(500, text="boom"))
    with pytest.raises(ElasticAPIError):
        await c.get_active_alerts()


def test_map_alert_basic_fields():
    c = _make_connector()
    hit = {
        "_id": "alert-123",
        "_source": {
            "@timestamp": "2026-05-08T01:23:45Z",
            "kibana.alert.rule.name": "Suspicious PowerShell",
            "kibana.alert.rule.uuid": "rule-uuid-abc",
            "kibana.alert.severity": "high",
            "threat": [{
                "tactic": {"name": "Execution"},
                "technique": [{"id": "T1059.001", "name": "PowerShell"}],
            }],
        },
    }
    ev = c.map_alert(hit, tenant_id="t-1")
    assert ev.tenant_id == "t-1"
    assert ev.source_event_id == "alert-123"
    assert ev.source_siem == "elastic"
    assert ev.severity == Severity.HIGH
    assert ev.title == "Suspicious PowerShell"
    assert ev.rule_name == "Suspicious PowerShell"
    assert ev.rule_id == "rule-uuid-abc"
    assert ev.mitre is not None
    assert ev.mitre.tactic == "Execution"
    assert ev.mitre.technique_id == "T1059.001"


def test_map_alert_missing_threat_handled_gracefully():
    c = _make_connector()
    hit = {
        "_id": "alert-noth",
        "_source": {
            "@timestamp": "2026-05-08T00:00:00Z",
            "kibana.alert.rule.name": "Bare alert",
            "kibana.alert.severity": "medium",
        },
    }
    ev = c.map_alert(hit, tenant_id="t-1")
    assert ev.mitre is None
    assert ev.severity == Severity.MEDIUM
    assert ev.title == "Bare alert"


def test_map_alert_handles_malformed_timestamp():
    c = _make_connector()
    hit = {
        "_id": "alert-bad-ts",
        "_source": {
            "@timestamp": "not-a-real-timestamp",
            "kibana.alert.rule.name": "x",
            "kibana.alert.severity": "low",
        },
    }
    ev = c.map_alert(hit, tenant_id="t-1")
    # Falls back to "now" — just assert it parsed to a tz-aware datetime.
    assert ev.timestamp.tzinfo is not None


def test_map_alert_severity_variants():
    c = _make_connector()
    cases = [
        ("critical", Severity.CRITICAL),
        ("HIGH", Severity.HIGH),
        ("Medium", Severity.MEDIUM),
        ("low", Severity.LOW),
        ("informational", Severity.INFO),
        ("unknown", Severity.UNKNOWN),
        (None, Severity.UNKNOWN),
    ]
    for raw, expected in cases:
        hit = {
            "_id": "x",
            "_source": {
                "@timestamp": "2026-05-08T00:00:00Z",
                "kibana.alert.rule.name": "rn",
                "kibana.alert.severity": raw,
            },
        }
        assert c.map_alert(hit, "t").severity == expected, raw
