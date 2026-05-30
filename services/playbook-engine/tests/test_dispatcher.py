"""Tests for the shared playbook dispatcher (auto + manual paths)."""

from __future__ import annotations

from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import pytest

from playbook_engine.dispatcher import coerce_tenant_uuid, dispatch_playbook
from playbook_engine.narrative_loader import Narrative, Playbook, PlaybookAction


class FakeStore:
    def __init__(self):
        self.created: list[dict] = []

    async def create_run(self, **kwargs):
        self.created.append(kwargs)
        return uuid4()


class FakeCfg:
    attack_state_engine_url = "http://ase"
    internal_api_key = "k"
    temporal_task_queue = "q"


def _narratives():
    pb = Playbook(
        narrative_id="AN-01",
        playbook_name="Lateral Movement Response",
        trigger="lateral-movement confirmed",
        immediate=[PlaybookAction(action_type="isolate_host", target="affected_host",
                                  description="Isolate the host")],
        follow_up=[],
    )
    return [Narrative(narrative_id="AN-01", name="LM", phases=["lateral-movement"],
                      raw={}, playbooks=[pb])]


def _attack(phase="lateral-movement", status="Confirmed", confidence=0.4):
    return {
        "attack_id": str(uuid4()),
        "tenant_id": str(uuid4()),
        "current_phase": phase,
        "confidence": confidence,
        "phases": [{"phase": phase, "status": status}],
        "hosts": ["HOST-1"],
        "users": ["user1"],
    }


@pytest.mark.asyncio
async def test_dispatch_creates_run_and_starts_workflow():
    store, tc = FakeStore(), AsyncMock()
    res = await dispatch_playbook(
        _attack(confidence=0.4), narratives=_narratives(), store=store,
        temporal_client=tc, cfg=FakeCfg(), trigger="manual",
    )
    assert res is not None
    assert res["trigger"] == "manual"
    assert res["narrative_id"] == "AN-01"
    assert res["action_count"] >= 1
    assert len(store.created) == 1
    tc.start_workflow.assert_awaited_once()
    # confidence 0.4 is BELOW the 0.7 escalation gate, yet it still dispatched —
    # manual run is not confidence-gated ("run 100% of the time").
    assert store.created[0]["confidence_at_trigger"] == 0.4


@pytest.mark.asyncio
async def test_dispatch_no_match_returns_none():
    store, tc = FakeStore(), AsyncMock()
    res = await dispatch_playbook(
        _attack(phase="reconnaissance"), narratives=_narratives(), store=store,
        temporal_client=tc, cfg=FakeCfg(), trigger="manual",
    )
    assert res is None
    assert store.created == []
    tc.start_workflow.assert_not_awaited()


def test_coerce_tenant_uuid():
    assert isinstance(coerce_tenant_uuid("free-form-tenant"), UUID)
    u = str(uuid4())
    assert str(coerce_tenant_uuid(u)) == u
