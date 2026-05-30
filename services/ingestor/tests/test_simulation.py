"""Tests for the agent-less attack-simulation engine."""

from __future__ import annotations

import pytest

from .. import main, simulation


def test_catalog_lists_scenarios():
    scs = simulation.list_scenarios()
    assert len(scs) >= 3
    ids = {s["id"] for s in scs}
    assert "lsass-to-lateral" in ids
    for s in scs:
        assert s["steps"] == len(s["expected_detections"])
        assert s["phases"]


def test_get_scenario():
    assert simulation.get_scenario("lsass-to-lateral") is not None
    assert simulation.get_scenario("nope") is None


def test_build_events_shape():
    sc = simulation.get_scenario("lsass-to-lateral")
    events = simulation.build_events(sc, "tenant-9", host="HX", user="ux")
    assert len(events) == len(sc["steps"])
    first = events[0]
    # tenant scoped, detection + state_impact set so correlation can place it
    assert first.tenant_id == "tenant-9"
    assert first.detection_id == "D1-LSASS-MEMORY-ACCESS"
    assert first.state_impact["transitions_to"] == "credential-access"
    assert first.host.hostname == "HX"
    assert "simulation" in first.tags
    # timestamps are strictly increasing across the kill chain
    ts = [e.timestamp for e in events]
    assert ts == sorted(ts)


class _FakeProducer:
    def __init__(self):
        self.batches = []

    def is_connected(self):
        return True

    async def publish_signals_batch(self, events):
        self.batches.append(events)
        return len(events)


class _FakeEngine:
    def __init__(self):
        self.producer = _FakeProducer()


@pytest.mark.asyncio
async def test_run_simulation_publishes_for_key_tenant(monkeypatch):
    async def fake_auth(_authorization):
        return "real-tenant"

    monkeypatch.setattr(main, "authenticate", fake_auth)
    monkeypatch.setattr(main, "engine", _FakeEngine())

    out = await main.run_simulation(
        main.SimulationRunRequest(scenario_id="powershell-discovery"),
        authorization="Bearer vgl_x",
    )
    assert out["published"] == 2
    assert out["expected_detections"] == ["D5-POWERSHELL-ENCODED-COMMAND", "D8-DOMAIN-ACCOUNT-DISCOVERY"]
    # events were tenant-scoped to the authenticated key, not the request body
    published = main.engine.producer.batches[0]
    assert all(e.tenant_id == "real-tenant" for e in published)


@pytest.mark.asyncio
async def test_run_simulation_unknown_scenario_404(monkeypatch):
    from fastapi import HTTPException

    async def fake_auth(_authorization):
        return "t"

    monkeypatch.setattr(main, "authenticate", fake_auth)
    monkeypatch.setattr(main, "engine", _FakeEngine())

    with pytest.raises(HTTPException) as ei:
        await main.run_simulation(
            main.SimulationRunRequest(scenario_id="does-not-exist"),
            authorization="Bearer vgl_x",
        )
    assert ei.value.status_code == 404
