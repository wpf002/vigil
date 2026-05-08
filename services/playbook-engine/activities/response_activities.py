"""Response activities — Temporal activity stubs.

Each activity logs at INFO with tenant_id + attack_id in context, sleeps
briefly to simulate work, and returns success. In production these would
call SOAR APIs (e.g. CrowdStrike isolate, Okta credential reset).
"""

from __future__ import annotations
import asyncio
from dataclasses import dataclass
from typing import Optional

import structlog
from temporalio import activity

logger = structlog.get_logger(__name__)


@dataclass
class ActivityResult:
    success: bool
    detail: str = ""


def _bind(tenant_id: str, attack_id: str, **extra) -> structlog.stdlib.BoundLogger:
    return logger.bind(tenant_id=tenant_id, attack_id=attack_id, **extra)


async def _simulate(action: str, tenant_id: str, attack_id: str, **kwargs) -> ActivityResult:
    log = _bind(tenant_id=tenant_id, attack_id=attack_id, action=action, **kwargs)
    log.info("playbook.activity.start")
    await asyncio.sleep(1)
    log.info("playbook.activity.complete")
    return ActivityResult(success=True, detail=f"{action} simulated")


@activity.defn
async def isolate_host(host: str, tenant_id: str, attack_id: str) -> bool:
    res = await _simulate("isolate_host", tenant_id, attack_id, host=host)
    return res.success


@activity.defn
async def kill_process(process: str, host: Optional[str], tenant_id: str, attack_id: str) -> bool:
    res = await _simulate("kill_process", tenant_id, attack_id, process=process, host=host)
    return res.success


@activity.defn
async def reset_credentials(user: str, tenant_id: str, attack_id: str) -> bool:
    res = await _simulate("reset_credentials", tenant_id, attack_id, user=user)
    return res.success


@activity.defn
async def capture_forensic_snapshot(host: str, tenant_id: str, attack_id: str) -> bool:
    res = await _simulate("capture_forensic_snapshot", tenant_id, attack_id, host=host)
    return res.success


@activity.defn
async def block_protocol(protocol: str, host: Optional[str], tenant_id: str, attack_id: str) -> bool:
    res = await _simulate("block_protocol", tenant_id, attack_id, protocol=protocol, host=host)
    return res.success


@activity.defn
async def review_auth_logs(host: str, tenant_id: str, attack_id: str) -> bool:
    res = await _simulate("review_auth_logs", tenant_id, attack_id, host=host)
    return res.success


@activity.defn
async def notify_attack_state_complete(
    base_url: str,
    internal_key: str,
    attack_id: str,
    action_index: int,
) -> bool:
    """Mark a recommended_action as completed on the AttackState.

    Calls POST /attacks/{attack_id}/actions/{action_index}/complete. Failures
    are non-fatal: the workflow continues even if attack-state-engine is
    momentarily unreachable.
    """
    import httpx
    url = f"{base_url.rstrip('/')}/attacks/{attack_id}/actions/{action_index}/complete"
    log = _bind(tenant_id="-", attack_id=attack_id, action_index=action_index)
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                url,
                headers={"X-Internal-Key": internal_key, "Authorization": f"Bearer internal:{internal_key}"},
            )
            if resp.status_code >= 400:
                log.warning("playbook.notify_complete.failed", status_code=resp.status_code)
                return False
        return True
    except Exception as e:
        log.warning("playbook.notify_complete.error", error=str(e))
        return False


# Registry of all activities the worker should expose. Keep this in sync
# with the @activity.defn definitions above.
ALL_ACTIVITIES = [
    isolate_host,
    kill_process,
    reset_credentials,
    capture_forensic_snapshot,
    block_protocol,
    review_auth_logs,
    notify_attack_state_complete,
]


# Map action_type → activity callable. Used by the workflow to dispatch
# without a giant if/elif. Activities not in this map are skipped with a
# warning so unknown YAML actions don't crash the workflow.
ACTIVITY_DISPATCH = {
    "isolate_host": isolate_host,
    "kill_process": kill_process,
    "reset_credentials": reset_credentials,
    "capture_forensic_snapshot": capture_forensic_snapshot,
    "block_protocol": block_protocol,
    "review_auth_logs": review_auth_logs,
}
