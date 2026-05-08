"""Tests for the VIGIL Python SDK client.

httpx is mocked via httpx.MockTransport so no real network calls happen.
Coverage:
  - list_attacks → AttackState dataclass conversion
  - get_attack → individual response shape
  - list_detections / get_coverage / get_executive_summary
  - submit_signal POST body shape
  - 404 → VIGILNotFoundError, 401/403 → VIGILAuthError, 429 → VIGILRateLimitError
"""

from __future__ import annotations
import json

import httpx
import pytest

from vigil_sdk import (
    VIGILAPIError,
    VIGILAuthError,
    VIGILClient,
    VIGILNotFoundError,
    VIGILRateLimitError,
)


def _client_with(handler) -> VIGILClient:
    transport = httpx.MockTransport(handler)
    return VIGILClient(
        api_key="vgl_test",
        base_url="http://api.example",
        attack_state_engine_url="http://ase.example",
        detection_engine_url="http://de.example",
        ingestor_url="http://ing.example",
        reporting_url="http://rep.example",
        playbook_engine_url="http://pl.example",
        client=httpx.Client(transport=transport),
    )


def test_list_attacks_unwraps_envelope():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.url.host == "ase.example"
        assert request.url.path == "/attacks"
        assert request.headers["Authorization"] == "Bearer vgl_test"
        return httpx.Response(
            200,
            json={
                "data": [
                    {"attack_id": "a-1", "tenant_id": "t-1", "name": "n",
                     "current_phase": "credential-access", "status": "active",
                     "confidence": 0.7},
                ],
                "meta": {"count": 1},
                "error": None,
            },
        )

    client = _client_with(handler)
    attacks = client.list_attacks(min_confidence=0.5, limit=10)
    assert len(attacks) == 1
    a = attacks[0]
    assert a.attack_id == "a-1"
    assert a.confidence == 0.7
    assert a.current_phase == "credential-access"


def test_get_attack_unwraps_dict():
    def handler(req):
        return httpx.Response(200, json={
            "data": {
                "attack_id": "a-2", "tenant_id": "t",
                "name": "n", "status": "resolved",
                "current_phase": "exfiltration", "confidence": 0.9,
            },
            "error": None,
        })
    client = _client_with(handler)
    a = client.get_attack("a-2")
    assert a.attack_id == "a-2"
    assert a.status == "resolved"


def test_list_detections_returns_dataclass_list():
    def handler(req):
        return httpx.Response(200, json={
            "data": [{
                "detection_id": "D1", "version": "1.0.0",
                "att_ck_tactic": "credential-access",
                "att_ck_technique": "T1110", "status": "active",
                "performance": {"fp_rate": 0.05},
            }],
            "error": None,
        })
    client = _client_with(handler)
    dets = client.list_detections()
    assert dets[0].fp_rate == 0.05
    assert dets[0].detection_id == "D1"


def test_get_coverage_returns_dict():
    def handler(req):
        return httpx.Response(200, json={
            "data": {"coverage_score": 0.62, "by_tactic": {"credential-access": 0.8}},
            "error": None,
        })
    client = _client_with(handler)
    cov = client.get_coverage()
    assert cov["coverage_score"] == 0.62


def test_executive_summary_dataclass():
    def handler(req):
        return httpx.Response(200, json={
            "data": {
                "active_attacks": 3, "attacks_resolved_7d": 7,
                "mttr_seconds_7d": 1234.5, "coverage_score": 0.5,
                "open_escalations": 2,
            },
            "error": None,
        })
    client = _client_with(handler)
    summary = client.get_executive_summary()
    assert summary.active_attacks == 3
    assert summary.attacks_resolved_7d == 7
    assert summary.mttr_seconds_7d == 1234.5


def test_submit_signal_posts_body():
    seen = {}

    def handler(req: httpx.Request):
        seen["method"] = req.method
        seen["url"] = str(req.url)
        seen["body"] = json.loads(req.content)
        return httpx.Response(200, json={"data": {"ok": True}, "error": None})

    client = _client_with(handler)
    out = client.submit_signal({"title": "x", "tenant_id": "t"})
    assert seen["method"] == "POST"
    assert seen["url"].startswith("http://ing.example/signals")
    assert seen["body"] == {"title": "x", "tenant_id": "t"}
    assert out == {"ok": True}


def test_list_playbooks_dataclass():
    def handler(req):
        return httpx.Response(200, json={
            "data": [{
                "run_id": "r-1", "attack_id": "a-1",
                "workflow_id": "wf-1", "narrative_id": "AN-001",
                "status": "running",
            }],
            "error": None,
        })
    client = _client_with(handler)
    runs = client.list_playbooks()
    assert runs[0].status == "running"
    assert runs[0].narrative_id == "AN-001"


# ── error taxonomy ────────────────────────────────────────────────────────


def test_404_raises_not_found():
    def handler(req):
        return httpx.Response(404, json={"error": "not found"})
    client = _client_with(handler)
    with pytest.raises(VIGILNotFoundError):
        client.get_attack("missing")


def test_401_raises_auth_error():
    def handler(req):
        return httpx.Response(401, json={"error": "unauthorized"})
    client = _client_with(handler)
    with pytest.raises(VIGILAuthError):
        client.list_attacks()


def test_403_raises_auth_error_on_scope():
    def handler(req):
        return httpx.Response(403, json={"error": "missing scope"})
    client = _client_with(handler)
    with pytest.raises(VIGILAuthError):
        client.list_attacks()


def test_429_raises_rate_limit():
    def handler(req):
        return httpx.Response(429, json={"error": "slow down"})
    client = _client_with(handler)
    with pytest.raises(VIGILRateLimitError):
        client.list_attacks()


def test_500_raises_generic_api_error():
    def handler(req):
        return httpx.Response(500, text="boom")
    client = _client_with(handler)
    with pytest.raises(VIGILAPIError):
        client.list_attacks()


def test_constructor_requires_api_key():
    with pytest.raises(ValueError):
        VIGILClient(api_key="")
