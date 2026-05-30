"""ResponseWorkflow — Temporal workflow that runs a playbook.

Inputs (ResponseWorkflowInput):
  attack_id            UUID of the AttackState
  tenant_id            UUID of the tenant
  run_id               UUID of the playbook_runs row
  actions              list[dict] — full action list from store
  attack_state_engine_url
  internal_api_key

Behavior:
  1. Partition actions into immediate vs follow_up by priority.
  2. Execute every immediate action (each as a Temporal activity).
  3. Then every follow_up action.
  4. After each successful action: notify attack-state-engine to mark
     recommended_actions[idx].completed = true.
  5. On any activity failure: pause the workflow (await resume signal).
     Resume signal continues from the failed action. Abort signal exits
     with status='failed'.

Signals:
  resume      — continue from pause
  abort       — exit immediately with failure
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from temporalio import workflow
from temporalio.common import RetryPolicy

# Workflow-safe imports (no I/O at import time).
with workflow.unsafe.imports_passed_through():
    from ..activities import response_activities


@dataclass
class ResponseWorkflowInput:
    attack_id: str
    tenant_id: str
    run_id: str
    actions: list[dict[str, Any]]
    attack_state_engine_url: str
    internal_api_key: str


@dataclass
class ResponseWorkflowResult:
    completed_action_indices: list[int]
    failed_action_index: int | None
    aborted: bool
    completed: bool


@workflow.defn(name="ResponseWorkflow")
class ResponseWorkflow:
    def __init__(self) -> None:
        self._paused = False
        self._aborted = False
        self._resume = False

    @workflow.signal
    def resume(self) -> None:
        self._paused = False
        self._resume = True

    @workflow.signal
    def abort(self) -> None:
        self._aborted = True
        self._paused = False

    @workflow.run
    async def run(self, inp: ResponseWorkflowInput) -> ResponseWorkflowResult:
        completed: list[int] = []
        failed: int | None = None

        # Stable ordering: enrichment (read-only context) first, then response
        # (state-changing); within each, immediate before follow_up.
        ordered: list[tuple[int, dict[str, Any]]] = sorted(
            enumerate(inp.actions),
            key=lambda item: (
                0 if item[1].get("kind") == "enrichment" else 1,
                0 if item[1].get("priority") == "immediate" else 1,
            ),
        )

        idx_pos = 0
        while idx_pos < len(ordered):
            if self._aborted:
                return ResponseWorkflowResult(
                    completed_action_indices=completed,
                    failed_action_index=failed,
                    aborted=True,
                    completed=False,
                )

            original_idx, action = ordered[idx_pos]
            try:
                ok = await self._execute_action(inp, action)
            except Exception:
                ok = False

            if not ok:
                failed = original_idx
                self._paused = True
                # Wait for resume or abort.
                await workflow.wait_condition(lambda: not self._paused or self._aborted)
                if self._aborted:
                    return ResponseWorkflowResult(
                        completed_action_indices=completed,
                        failed_action_index=failed,
                        aborted=True,
                        completed=False,
                    )
                if self._resume:
                    # Retry the same action on resume.
                    self._resume = False
                    continue

            completed.append(original_idx)

            # Notify attack-state-engine; intentionally fire-and-forget at
            # this layer — the activity itself logs failures.
            await workflow.execute_activity(
                response_activities.notify_attack_state_complete,
                args=[
                    inp.attack_state_engine_url,
                    inp.internal_api_key,
                    inp.attack_id,
                    original_idx,
                ],
                start_to_close_timeout=timedelta(seconds=15),
                retry_policy=RetryPolicy(maximum_attempts=3),
            )

            idx_pos += 1

        return ResponseWorkflowResult(
            completed_action_indices=completed,
            failed_action_index=failed,
            aborted=False,
            completed=True,
        )

    async def _execute_action(
        self,
        inp: ResponseWorkflowInput,
        action: dict[str, Any],
    ) -> bool:
        action_type = str(action.get("action_type") or "")
        target = str(action.get("target_entity") or "")

        activity_callable = response_activities.ACTIVITY_DISPATCH.get(action_type)
        if activity_callable is None:
            workflow.logger.warning(
                f"playbook.workflow.unknown_action action_type={action_type}"
            )
            # Treat unknown actions as success so we don't pause forever on
            # YAML drift — analyst can still mark complete from the UI.
            return True

        # Build the positional argument list per activity signature.
        # All activities end with (..., tenant_id, attack_id).
        if action_type == "isolate_host":
            args: list[Any] = [target, inp.tenant_id, inp.attack_id]
        elif action_type == "kill_process":
            args = [target, action.get("host"), inp.tenant_id, inp.attack_id]
        elif action_type == "reset_credentials":
            args = [target, inp.tenant_id, inp.attack_id]
        elif action_type == "capture_forensic_snapshot":
            args = [target, inp.tenant_id, inp.attack_id]
        elif action_type == "block_protocol":
            protocol = action.get("protocol") or target
            args = [protocol, action.get("host"), inp.tenant_id, inp.attack_id]
        elif action_type == "review_auth_logs":
            args = [target, inp.tenant_id, inp.attack_id]
        else:
            # Generic single-target dispatch for any other registered activity
            # (e.g. enrichment: ioc_lookup / asset_context / user_context).
            # Adding such an action no longer requires editing this workflow.
            args = [target, inp.tenant_id, inp.attack_id]

        result = await workflow.execute_activity(
            activity_callable,
            args=args,
            start_to_close_timeout=timedelta(minutes=2),
            retry_policy=RetryPolicy(maximum_attempts=2),
        )
        return bool(result)
