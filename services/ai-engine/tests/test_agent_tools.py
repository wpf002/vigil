"""Tests for the agent-less retrieval loop (Big Bet 3) — gated + spend-safe."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from ai_engine import agent_tools


# ── fakes (no real Anthropic calls) ──────────────────────────────────────────
def _text(t):
    return SimpleNamespace(type="text", text=t)


def _tool(name, inp, _id="tu1"):
    return SimpleNamespace(type="tool_use", name=name, input=inp, id=_id)


def _resp(content, i=100, o=50):
    return SimpleNamespace(content=content, usage=SimpleNamespace(input_tokens=i, output_tokens=o))


class _FakeMessages:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = 0

    def create(self, **kw):
        r = self.responses[min(self.calls, len(self.responses) - 1)]
        self.calls += 1
        return r


class _FakeClient:
    def __init__(self, responses):
        self.messages = _FakeMessages(responses)


class _FakeBudget:
    def __init__(self, allow=True, limit=50):
        self.allow = allow
        self.limit = limit
        self.calls = 0

    async def try_consume(self):
        self.calls += 1
        return (self.allow, self.calls)


async def _run(client, budget, **kw):
    defaults = dict(hypothesis="LSASS dump on SRV-01", tenant_id="t",
                    client=client, model="m", budget=budget, narrator_enabled=True)
    defaults.update(kw)
    return await agent_tools.run_investigation(**defaults)


def test_disabled_by_default(monkeypatch):
    monkeypatch.delenv(agent_tools.RETRIEVAL_ENABLED_ENV, raising=False)
    assert agent_tools.retrieval_enabled() is False


def test_enabled_only_when_explicitly_true(monkeypatch):
    monkeypatch.setenv(agent_tools.RETRIEVAL_ENABLED_ENV, "true")
    assert agent_tools.retrieval_enabled() is True
    monkeypatch.setenv(agent_tools.RETRIEVAL_ENABLED_ENV, "false")
    assert agent_tools.retrieval_enabled() is False


def test_build_plan_is_pure_and_exposes_tools(monkeypatch):
    monkeypatch.delenv(agent_tools.RETRIEVAL_ENABLED_ENV, raising=False)
    plan = agent_tools.build_plan("LSASS dump on FILESERVER-03")
    assert "LSASS dump on FILESERVER-03" in plan["user"]
    names = {t["name"] for t in plan["tools"]}
    assert {"run_splunk_search", "query_sentinel", "list_cloud_logs"} <= names
    assert plan["enabled"] is False  # never on by default
    assert plan["max_steps"] >= 1


# ── the loop: spend-safety guarantees ────────────────────────────────────────
@pytest.mark.asyncio
async def test_disabled_makes_no_claude_call(monkeypatch):
    monkeypatch.delenv(agent_tools.RETRIEVAL_ENABLED_ENV, raising=False)
    client, budget = _FakeClient([]), _FakeBudget()
    res = await _run(client, budget)
    assert res["enabled"] is False
    assert client.messages.calls == 0  # ZERO Claude calls
    assert budget.calls == 0


@pytest.mark.asyncio
async def test_kill_switch_makes_no_claude_call(monkeypatch):
    monkeypatch.setenv(agent_tools.RETRIEVAL_ENABLED_ENV, "true")
    client, budget = _FakeClient([_resp([_text("hi")])]), _FakeBudget()
    res = await _run(client, budget, narrator_enabled=False)
    assert res["enabled"] is False
    assert client.messages.calls == 0


@pytest.mark.asyncio
async def test_runs_tool_then_answers(monkeypatch):
    monkeypatch.setenv(agent_tools.RETRIEVAL_ENABLED_ENV, "true")
    responses = [
        _resp([_tool("run_splunk_search", {"spl": "index=main lsass"})], i=100, o=50),
        _resp([_text("Hypothesis confirmed: LSASS access observed.")], i=80, o=40),
    ]
    client, budget = _FakeClient(responses), _FakeBudget(allow=True)
    res = await _run(client, budget)
    assert res["enabled"] is True and res["stopped"] == "answered"
    assert "confirmed" in res["final"].lower()
    assert res["steps"] == 2
    assert budget.calls == 2          # budget consumed BEFORE each Claude call
    assert res["tokens"] == 270       # token accounting works
    events = [e["event"] for e in res["transcript"]]
    assert "tool" in events and "final" in events


@pytest.mark.asyncio
async def test_budget_exhausted_stops_before_calling(monkeypatch):
    monkeypatch.setenv(agent_tools.RETRIEVAL_ENABLED_ENV, "true")
    client = _FakeClient([_resp([_text("hi")])])
    res = await _run(client, _FakeBudget(allow=False))
    assert res["stopped"] == "budget"
    assert client.messages.calls == 0  # budget gate runs BEFORE the call


@pytest.mark.asyncio
async def test_step_cap_bounds_the_loop(monkeypatch):
    monkeypatch.setenv(agent_tools.RETRIEVAL_ENABLED_ENV, "true")
    # always asks for a tool -> never answers; must be bounded by max_steps
    looping = [_resp([_tool("list_cloud_logs", {})]) for _ in range(20)]
    client, budget = _FakeClient(looping), _FakeBudget(allow=True)
    res = await _run(client, budget, max_steps=3)
    assert res["stopped"] == "max_steps"
    assert res["steps"] == 3
    assert client.messages.calls == 3 and budget.calls == 3
