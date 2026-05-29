"""Tests for the reporting service.

Mocks httpx + asyncpg. Coverage:
  - SOC 2 evidence pack contains required criteria keys (CC6/CC7/CC8)
  - PCI pack contains correct requirement numbers (10/11)
  - NIST pack covers all five functions
  - Aggregator handles zero-attack tenants gracefully
  - Cache returns cached value on second call
  - SnapshotScheduler.persist writes correct period boundaries
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID, uuid4

import pytest

from reporting.aggregator import Aggregator
from reporting.cache import TenantCache
from reporting.compliance import ComplianceAssembler
from reporting.scheduler import SnapshotScheduler

# ── stub httpx client ─────────────────────────────────────────────────────


class StubResp:
    def __init__(self, status_code: int = 200, body: Any = None):
        self.status_code = status_code
        self._body = body

    def json(self):
        return self._body


class StubClient:
    """Async-context-manager-compatible httpx stand-in. The script maps URL
    suffixes to canned responses so each upstream service is independent."""

    def __init__(self, routes: dict[str, StubResp]):
        self.routes = routes
        self.calls: list[tuple[str, dict, dict]] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return None

    async def get(self, url: str, headers=None, params=None):
        self.calls.append((url, dict(headers or {}), dict(params or {})))
        for suffix, resp in self.routes.items():
            if url.endswith(suffix):
                return resp
        return StubResp(404, {"error": "no route"})


def _client_factory(client: StubClient):
    return lambda: client


# ── compliance: SOC 2 ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_soc2_contains_required_criteria_keys():
    client = StubClient({
        "/auth/users": StubResp(200, [
            {"user_id": "u-1", "email": "a@b.c", "role": "admin", "last_login": None}
        ]),
        "/attacks": StubResp(200, []),
        "/coverage": StubResp(200, {"data": {"coverage_score": 0.5}}),
        "/detections": StubResp(200, []),
    })
    asm = ComplianceAssembler(
        api_url="http://api", attack_state_engine_url="http://ase",
        detection_engine_url="http://de", analyst_portal_url="http://ap",
        client_factory=_client_factory(client),
    )
    pack = await asm.soc2(uuid4())
    assert pack["framework"] == "SOC 2 Type II"
    criteria_names = [c["criterion"] for c in pack["criteria"]]
    assert any("CC6" in n for n in criteria_names)
    assert any("CC7" in n for n in criteria_names)
    assert any("CC8" in n for n in criteria_names)


@pytest.mark.asyncio
async def test_pci_contains_correct_requirement_numbers():
    client = StubClient({
        "/transitions/count": StubResp(200, {"count": 17}),
        "/coverage": StubResp(200, {"score": 0.8}),
        "/detections": StubResp(200, [
            {"detection_id": "D1", "deployed_at": "2026-05-01T00:00:00Z"},
            {"detection_id": "D2", "deployed_at": "2026-05-02T00:00:00Z"},
        ]),
    })
    asm = ComplianceAssembler(
        api_url="http://api", attack_state_engine_url="http://ase",
        detection_engine_url="http://de", analyst_portal_url="http://ap",
        client_factory=_client_factory(client),
    )
    pack = await asm.pci(uuid4())
    reqs = [c["requirement"] for c in pack["criteria"]]
    assert any("Req 10" in r for r in reqs)
    assert any("Req 11" in r for r in reqs)
    # Last deployment timestamp picked.
    sec_test = next(c for c in pack["criteria"] if "Req 11" in c["requirement"])
    assert sec_test["evidence"]["last_detection_deployment"] == "2026-05-02T00:00:00Z"


@pytest.mark.asyncio
async def test_nist_covers_all_five_functions():
    client = StubClient({
        "/coverage": StubResp(200, {"by_tactic": {"credential-access": 0.9}}),
        "/detections": StubResp(200, [
            {"detection_id": "D1", "status": "active",
             "performance": {"total_fires": 10, "fp_rate": 0.1}},
        ]),
        "/attacks": StubResp(200, []),
    })
    asm = ComplianceAssembler(
        api_url="http://api", attack_state_engine_url="http://ase",
        detection_engine_url="http://de", analyst_portal_url="http://ap",
        client_factory=_client_factory(client),
    )
    pack = await asm.nist(uuid4())
    funcs = pack["functions"]
    assert set(funcs.keys()) == {"Identify", "Protect", "Detect", "Respond", "Recover"}
    assert funcs["Detect"]["detection_fires_total"] == 10


# ── aggregator: zero-attack tenant ────────────────────────────────────────


@pytest.mark.asyncio
async def test_aggregator_zero_attack_tenant_returns_safe_defaults():
    client = StubClient({
        "/attacks": StubResp(200, []),
        "/coverage": StubResp(200, {"coverage_score": 0.0, "detections": []}),
        "/queue": StubResp(200, []),
    })
    agg = Aggregator(
        attack_state_engine_url="http://ase",
        detection_engine_url="http://de",
        analyst_portal_url="http://ap",
        api_url="http://api",
        client_factory=_client_factory(client),
    )
    summary = await agg.executive_summary(uuid4())
    assert summary["active_attacks"] == 0
    assert summary["attacks_resolved_7d"] == 0
    assert summary["mttr_seconds_7d"] is None
    assert summary["coverage_score"] == 0.0


@pytest.mark.asyncio
async def test_aggregator_counts_attacks_by_phase_and_resolved():
    now = datetime.now(timezone.utc)
    earlier = now - timedelta(hours=4)
    attacks = [
        {
            "current_phase": "credential-access", "status": "active",
            "opened_at": earlier.isoformat(),
        },
        {
            "current_phase": "lateral-movement", "status": "resolved",
            "opened_at": (now - timedelta(hours=10)).isoformat(),
            "resolved_at": (now - timedelta(hours=2)).isoformat(),
        },
    ]
    client = StubClient({
        "/attacks": StubResp(200, attacks),
        "/coverage": StubResp(200, {}),
        "/queue": StubResp(200, []),
    })
    agg = Aggregator(
        attack_state_engine_url="http://ase",
        detection_engine_url="http://de",
        analyst_portal_url="http://ap",
        api_url="http://api",
        client_factory=_client_factory(client),
    )
    summary = await agg.executive_summary(uuid4())
    assert summary["active_attacks"] == 1
    assert summary["attacks_resolved_7d"] == 1
    assert summary["mttr_seconds_7d"] is not None
    # Phase distribution reflects only currently-active attacks, so the
    # resolved lateral-movement attack is excluded (see aggregator.py).
    assert summary["attacks_by_phase"] == {
        "credential-access": 1,
    }


# ── cache ─────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_cache_returns_cached_value_on_second_call():
    redis = MagicMock()
    redis.get = AsyncMock(return_value=None)
    redis.setex = AsyncMock(return_value=True)
    cache = TenantCache(redis_client=redis, ttl_seconds=300)

    # First call: miss.
    assert await cache.get("t-1", "summary") is None
    await cache.set("t-1", "summary", {"x": 1})
    redis.setex.assert_awaited_once()
    args = redis.setex.await_args.args
    assert args[0] == "reporting:t-1:summary"
    assert args[1] == 300

    # Second call: redis returns the previously-stored payload.
    redis.get = AsyncMock(return_value=json.dumps({"x": 1}).encode())
    cache = TenantCache(redis_client=redis, ttl_seconds=300)
    cached = await cache.get("t-1", "summary")
    assert cached == {"x": 1}


# ── scheduler.persist writes correct period boundaries ──────────────────


@pytest.mark.asyncio
async def test_scheduler_persist_writes_daily_period():
    pool = MagicMock()
    conn = MagicMock()
    new_id = uuid4()
    conn.fetchrow = AsyncMock(return_value={"snapshot_id": new_id})
    acquire = MagicMock()
    acquire.__aenter__ = AsyncMock(return_value=conn)
    acquire.__aexit__ = AsyncMock(return_value=False)
    pool.acquire = MagicMock(return_value=acquire)

    agg = MagicMock()
    sched = SnapshotScheduler(pool=pool, aggregator=agg, hour_utc=0, minute_utc=5)
    rid = await sched.persist(
        tenant_id=uuid4(), snapshot_type="daily", metrics={"x": 1}
    )
    assert rid == new_id
    args = conn.fetchrow.await_args.args
    # period_start ≈ period_end - 1 day for daily.
    period_start, period_end = args[3], args[4]
    delta = period_end - period_start
    assert abs(delta - timedelta(days=1)) < timedelta(seconds=2)


@pytest.mark.asyncio
async def test_scheduler_persist_writes_weekly_period():
    pool = MagicMock()
    conn = MagicMock()
    conn.fetchrow = AsyncMock(return_value={"snapshot_id": uuid4()})
    acquire = MagicMock()
    acquire.__aenter__ = AsyncMock(return_value=conn)
    acquire.__aexit__ = AsyncMock(return_value=False)
    pool.acquire = MagicMock(return_value=acquire)

    agg = MagicMock()
    sched = SnapshotScheduler(pool=pool, aggregator=agg, hour_utc=0, minute_utc=5)
    await sched.persist(
        tenant_id=uuid4(), snapshot_type="weekly", metrics={}
    )
    args = conn.fetchrow.await_args.args
    period_start, period_end = args[3], args[4]
    assert abs((period_end - period_start) - timedelta(days=7)) < timedelta(seconds=2)


# ── audit log passthrough ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_audit_log_passthrough_returns_entries():
    entries = [
        {"event_type": "user.login", "user_id": "u-1", "created_at": "2026-05-08T00:00:00Z"},
    ]
    client = StubClient({"/auth/audit-log": StubResp(200, {"data": entries})})
    asm = ComplianceAssembler(
        api_url="http://api", attack_state_engine_url="http://ase",
        detection_engine_url="http://de", analyst_portal_url="http://ap",
        client_factory=_client_factory(client),
    )
    out = await asm.audit_log(uuid4(), days=30, event_type="user.login")
    assert out == entries
