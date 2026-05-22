"""Tests for the playbook-engine.

Covers:
  - narrative_loader: parses YAML, picks correct playbook by phase + status
  - store: write/read contract via mocked asyncpg
  - ResponseWorkflow: immediate-then-followup ordering, activity failure
    pauses, resume signal continues, abort signal exits cleanly

The workflow tests use temporalio.testing.WorkflowEnvironment.from_time_skipping(),
which runs an in-memory time-skipping Temporal core without the network.
Activities are mocked so attack-state-engine and SOAR APIs are not touched.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

# ── narrative_loader ──────────────────────────────────────────────────────────

def test_load_narratives_reads_an_001(tmp_path):
    """Real AN-001 YAML must round-trip through the loader."""
    from playbook_engine.narrative_loader import load_narratives

    yaml_content = """
narrative_id: AN-001
name: Credential Access → Lateral Movement
phases:
  - phase: credential-access
  - phase: lateral-movement
response_playbooks:
  credential_access_confirmed:
    trigger: "phase=credential-access AND status=Confirmed AND confidence>=0.65"
    immediate:
      - action: isolate_host
        target: affected_host
        automated: false
      - action: kill_process
        target: dump_process
        automated: false
    follow_up:
      - action: reset_credentials
        target: affected_user
  lateral_movement_observed:
    trigger: "phase=lateral-movement AND status=Observed"
    immediate:
      - action: isolate_host
        target: source_host
    follow_up:
      - action: block_protocol
        target: smb_lateral
        protocol: SMB
"""
    f = tmp_path / "AN-001.yaml"
    f.write_text(yaml_content, encoding="utf-8")

    nars = load_narratives(tmp_path)
    assert len(nars) == 1
    n = nars[0]
    assert n.narrative_id == "AN-001"
    assert n.phases == ["credential-access", "lateral-movement"]
    assert len(n.playbooks) == 2

    cred = next(pb for pb in n.playbooks if pb.playbook_name == "credential_access_confirmed")
    assert len(cred.immediate) == 2
    assert cred.immediate[0].action_type == "isolate_host"
    assert len(cred.follow_up) == 1


def test_select_playbook_matches_by_phase_and_status(tmp_path):
    from playbook_engine.narrative_loader import load_narratives, select_playbook

    yaml_content = """
narrative_id: AN-001
phases:
  - phase: credential-access
  - phase: lateral-movement
response_playbooks:
  credential_access_confirmed:
    trigger: "phase=credential-access AND status=Confirmed"
    immediate:
      - action: isolate_host
        target: affected_host
  lateral_movement_observed:
    trigger: "phase=lateral-movement AND status=Observed"
    immediate:
      - action: isolate_host
        target: source_host
"""
    f = tmp_path / "AN-001.yaml"
    f.write_text(yaml_content, encoding="utf-8")
    nars = load_narratives(tmp_path)

    pick = select_playbook(nars, phase="credential-access", status="Confirmed")
    assert pick is not None
    assert pick.playbook_name == "credential_access_confirmed"

    pick = select_playbook(nars, phase="lateral-movement", status="Observed")
    assert pick is not None
    assert pick.playbook_name == "lateral_movement_observed"


def test_select_playbook_returns_none_when_no_match(tmp_path):
    from playbook_engine.narrative_loader import load_narratives, select_playbook

    yaml_content = """
narrative_id: AN-001
phases:
  - phase: credential-access
response_playbooks:
  credential_access_confirmed:
    trigger: "phase=credential-access AND status=Confirmed"
    immediate:
      - action: isolate_host
        target: affected_host
"""
    f = tmp_path / "AN-001.yaml"
    f.write_text(yaml_content, encoding="utf-8")
    nars = load_narratives(tmp_path)

    assert select_playbook(nars, phase="exfiltration") is None


def test_render_actions_resolves_targets(tmp_path):
    from playbook_engine.narrative_loader import (
        load_narratives,
        render_actions_for,
        select_playbook,
    )

    yaml_content = """
narrative_id: AN-001
phases:
  - phase: credential-access
response_playbooks:
  credential_access_confirmed:
    trigger: "phase=credential-access"
    immediate:
      - action: isolate_host
        target: affected_host
    follow_up:
      - action: reset_credentials
        target: affected_user
"""
    f = tmp_path / "AN-001.yaml"
    f.write_text(yaml_content, encoding="utf-8")
    nars = load_narratives(tmp_path)
    pb = select_playbook(nars, phase="credential-access")
    assert pb is not None

    actions = render_actions_for(pb, primary_host="dc01.corp", primary_user="alice")
    assert len(actions) == 2
    assert actions[0]["action_type"] == "isolate_host"
    assert actions[0]["priority"] == "immediate"
    assert actions[0]["target_entity"] == "dc01.corp"
    assert actions[1]["action_type"] == "reset_credentials"
    assert actions[1]["priority"] == "follow_up"
    assert actions[1]["target_entity"] == "alice"


# ── store: writes & reads via mocked asyncpg ──────────────────────────────────

@pytest.mark.asyncio
async def test_store_create_run_returns_id():
    from playbook_engine.store import PlaybookStore

    pool = MagicMock()
    conn = MagicMock()
    expected = uuid4()
    conn.fetchrow = AsyncMock(return_value={"run_id": expected})
    acquire = MagicMock()
    acquire.__aenter__ = AsyncMock(return_value=conn)
    acquire.__aexit__ = AsyncMock(return_value=False)
    pool.acquire = MagicMock(return_value=acquire)

    store = PlaybookStore(pool)
    rid = await store.create_run(
        attack_id=uuid4(),
        tenant_id=uuid4(),
        workflow_id="playbook-x",
        narrative_id="AN-001",
        phase_at_trigger="credential-access",
        confidence_at_trigger=0.81,
        actions=[{"action_type": "isolate_host"}],
    )
    assert rid == expected
    conn.fetchrow.assert_awaited_once()


@pytest.mark.asyncio
async def test_store_mark_status_completed_sets_timestamp():
    from playbook_engine.store import PlaybookStore

    pool = MagicMock()
    conn = MagicMock()
    conn.execute = AsyncMock()
    acquire = MagicMock()
    acquire.__aenter__ = AsyncMock(return_value=conn)
    acquire.__aexit__ = AsyncMock(return_value=False)
    pool.acquire = MagicMock(return_value=acquire)

    store = PlaybookStore(pool)
    await store.mark_status(uuid4(), "completed")
    args = conn.execute.call_args.args
    # 4th positional arg = completed_at
    assert isinstance(args[3], datetime)


@pytest.mark.asyncio
async def test_store_get_run_decodes_jsonb_strings():
    from playbook_engine.store import PlaybookStore

    pool = MagicMock()
    conn = MagicMock()
    rid = uuid4()
    aid = uuid4()
    tid = uuid4()
    raw_row = {
        "run_id": rid,
        "attack_id": aid,
        "tenant_id": tid,
        "workflow_id": "playbook-x",
        "narrative_id": "AN-001",
        "triggered_at": datetime.now(timezone.utc),
        "status": "running",
        "phase_at_trigger": "credential-access",
        "confidence_at_trigger": 0.85,
        "completed_at": None,
        "actions": '[{"action_type": "isolate_host"}]',
        "completed_actions": "[]",
    }
    conn.fetchrow = AsyncMock(return_value=raw_row)
    acquire = MagicMock()
    acquire.__aenter__ = AsyncMock(return_value=conn)
    acquire.__aexit__ = AsyncMock(return_value=False)
    pool.acquire = MagicMock(return_value=acquire)

    store = PlaybookStore(pool)
    row = await store.get_run(rid, tid)
    assert row is not None
    assert isinstance(row["actions"], list)
    assert row["actions"][0]["action_type"] == "isolate_host"
    assert row["completed_actions"] == []


# ── ResponseWorkflow tests via in-memory Temporal env ─────────────────────────

# Skip workflow-environment tests if temporalio is missing or the local
# binary cannot be downloaded (e.g. offline CI). The unit tests above
# already cover the bulk of business logic.
temporalio = pytest.importorskip("temporalio")
import pytest_asyncio  # noqa: E402
from temporalio import activity  # noqa: E402
from temporalio.client import WorkflowFailureError  # noqa: E402
from temporalio.testing import WorkflowEnvironment  # noqa: E402
from temporalio.worker import Worker  # noqa: E402

from playbook_engine.activities import response_activities  # noqa: E402
from playbook_engine.workflows.response_workflow import (  # noqa: E402
    ResponseWorkflow,
    ResponseWorkflowInput,
    ResponseWorkflowResult,
)


def _make_actions() -> list[dict[str, Any]]:
    """Two immediate + one follow_up so order can be verified."""
    return [
        {"action_type": "isolate_host", "priority": "follow_up", "target_entity": "host-A"},
        {"action_type": "isolate_host", "priority": "immediate", "target_entity": "host-B"},
        {"action_type": "isolate_host", "priority": "immediate", "target_entity": "host-C"},
    ]


# Mock activity definitions used in place of the real ones.
_RECORDED: list[str] = []
_FAIL_ON: set[str] = set()


@activity.defn(name="isolate_host")
async def fake_isolate_host(host: str, tenant_id: str, attack_id: str) -> bool:
    _RECORDED.append(f"isolate_host:{host}")
    if host in _FAIL_ON:
        raise RuntimeError(f"forced failure on {host}")
    return True


@activity.defn(name="notify_attack_state_complete")
async def fake_notify(base_url: str, internal_key: str, attack_id: str, action_index: int) -> bool:
    _RECORDED.append(f"notify:{action_index}")
    return True


def _reset_recordings() -> None:
    _RECORDED.clear()
    _FAIL_ON.clear()


@pytest_asyncio.fixture
async def wf_env():
    """Time-skipping Temporal env. Falls back to skip if the binary can't load."""
    try:
        env = await WorkflowEnvironment.start_time_skipping()
    except Exception as e:  # pragma: no cover — depends on Temporal toolchain
        pytest.skip(f"Temporal time-skipping env unavailable: {e}")
    try:
        yield env
    finally:
        await env.shutdown()


@pytest.mark.asyncio
async def test_workflow_runs_immediate_before_follow_up(wf_env):
    _reset_recordings()
    inp = ResponseWorkflowInput(
        attack_id=str(uuid4()),
        tenant_id=str(uuid4()),
        run_id=str(uuid4()),
        actions=_make_actions(),
        attack_state_engine_url="http://attack-state-engine",
        internal_api_key="x",
    )
    async with Worker(
        wf_env.client,
        task_queue="vigil-test-q",
        workflows=[ResponseWorkflow],
        activities=[fake_isolate_host, fake_notify],
    ):
        result: ResponseWorkflowResult = await wf_env.client.execute_workflow(
            ResponseWorkflow.run,
            inp,
            id=f"wf-{uuid4()}",
            task_queue="vigil-test-q",
        )
    assert result.completed is True
    assert result.aborted is False
    # Immediate (host-B, host-C) must run before follow_up (host-A).
    isolate_order = [r for r in _RECORDED if r.startswith("isolate_host")]
    assert isolate_order == [
        "isolate_host:host-B",
        "isolate_host:host-C",
        "isolate_host:host-A",
    ]


@pytest.mark.asyncio
async def test_workflow_pauses_on_activity_failure_then_aborts(wf_env):
    _reset_recordings()
    _FAIL_ON.add("host-B")  # immediate action fails on first try

    inp = ResponseWorkflowInput(
        attack_id=str(uuid4()),
        tenant_id=str(uuid4()),
        run_id=str(uuid4()),
        actions=_make_actions(),
        attack_state_engine_url="http://attack-state-engine",
        internal_api_key="x",
    )

    async with Worker(
        wf_env.client,
        task_queue="vigil-test-q",
        workflows=[ResponseWorkflow],
        activities=[fake_isolate_host, fake_notify],
    ):
        handle = await wf_env.client.start_workflow(
            ResponseWorkflow.run,
            inp,
            id=f"wf-{uuid4()}",
            task_queue="vigil-test-q",
        )

        # Wait for the workflow to enter the paused state. The retry policy
        # makes the activity attempt twice before failing the workflow step,
        # so give it time.
        await asyncio.sleep(0.5)

        await handle.signal("abort")
        result: ResponseWorkflowResult = await handle.result()

    assert result.aborted is True
    assert result.completed is False
    assert result.failed_action_index is not None


@pytest.mark.asyncio
async def test_workflow_resume_continues_after_pause(wf_env):
    _reset_recordings()
    _FAIL_ON.add("host-B")  # fails first, then we clear and resume

    inp = ResponseWorkflowInput(
        attack_id=str(uuid4()),
        tenant_id=str(uuid4()),
        run_id=str(uuid4()),
        actions=_make_actions(),
        attack_state_engine_url="http://attack-state-engine",
        internal_api_key="x",
    )

    async with Worker(
        wf_env.client,
        task_queue="vigil-test-q",
        workflows=[ResponseWorkflow],
        activities=[fake_isolate_host, fake_notify],
    ):
        handle = await wf_env.client.start_workflow(
            ResponseWorkflow.run,
            inp,
            id=f"wf-{uuid4()}",
            task_queue="vigil-test-q",
        )

        await asyncio.sleep(0.5)
        # Clear the failure and resume.
        _FAIL_ON.discard("host-B")
        await handle.signal("resume")
        result: ResponseWorkflowResult = await handle.result()

    assert result.completed is True
    assert result.aborted is False
    # All three actions eventually completed.
    assert len(result.completed_action_indices) == 3
