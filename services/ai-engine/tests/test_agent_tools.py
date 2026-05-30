"""Tests for the agent-less retrieval scaffold (Big Bet 3) — gated + pure."""

from __future__ import annotations

from ai_engine import agent_tools


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
