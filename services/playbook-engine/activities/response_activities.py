"""Response activities — dispatch to SOAR backend or stub.

Each activity dispatches based on the SOAR_BACKEND env var:
  "stub"   → existing log-and-sleep behavior (default; used in dev/tests)
  "xsoar"  → Cortex XSOAR REST client
  "tines"  → Tines webhook client

On failure the activity raises so Temporal can pause the workflow and
notify analysts. Stub mode is unchanged from earlier phases — existing
tests continue to pass.
"""

from __future__ import annotations

import asyncio
import json
import os
from dataclasses import dataclass
from typing import Any, Optional
from uuid import UUID

import structlog
from temporalio import activity

logger = structlog.get_logger(__name__)


@dataclass
class ActivityResult:
    success: bool
    detail: str = ""


def _bind(tenant_id: str, attack_id: str, **extra) -> structlog.stdlib.BoundLogger:
    return logger.bind(tenant_id=tenant_id, attack_id=attack_id, **extra)


def _backend() -> str:
    return (os.getenv("SOAR_BACKEND") or "stub").lower()


def _xsoar_client():
    from ..soar.xsoar import XSOARClient
    base = os.getenv("XSOAR_BASE_URL") or ""
    key = os.getenv("XSOAR_API_KEY") or ""
    if not base or not key:
        raise RuntimeError("SOAR_BACKEND=xsoar requires XSOAR_BASE_URL and XSOAR_API_KEY")
    return XSOARClient(base_url=base, api_key=key)


def _tines_client():
    from ..soar.tines import TinesClient
    webhooks = {
        "isolate_host":              os.getenv("TINES_WEBHOOK_ISOLATE_HOST", ""),
        "kill_process":              os.getenv("TINES_WEBHOOK_KILL_PROCESS", ""),
        "reset_credentials":         os.getenv("TINES_WEBHOOK_RESET_CREDENTIALS", ""),
        "capture_forensic_snapshot": os.getenv("TINES_WEBHOOK_FORENSIC_SNAPSHOT", ""),
        "block_protocol":            os.getenv("TINES_WEBHOOK_BLOCK_PROTOCOL", ""),
        "review_auth_logs":          os.getenv("TINES_WEBHOOK_REVIEW_AUTH_LOGS", ""),
    }
    return TinesClient(api_key=os.getenv("TINES_API_KEY"), webhooks=webhooks)


async def _stub(action: str, tenant_id: str, attack_id: str, **kwargs) -> dict[str, Any]:
    log = _bind(tenant_id=tenant_id, attack_id=attack_id, action=action, backend="stub", **kwargs)
    log.info("playbook.activity.start")
    await asyncio.sleep(1)
    log.info("playbook.activity.complete")
    return {"success": True, "backend": "stub", "reference_id": None}


async def _dispatch(action: str, *, tenant_id: str, attack_id: str, **kwargs) -> dict[str, Any]:
    backend = _backend()
    if backend == "stub":
        return await _stub(action, tenant_id, attack_id, **kwargs)
    if backend == "xsoar":
        client = _xsoar_client()
        method = getattr(client, action)
        return await method(tenant_id=tenant_id, attack_id=attack_id, **kwargs)
    if backend == "tines":
        client = _tines_client()
        method = getattr(client, action)
        return await method(tenant_id=tenant_id, attack_id=attack_id, **kwargs)
    raise RuntimeError(f"Unknown SOAR_BACKEND: {backend}")


# ── temporal activity wrappers ────────────────────────────────────────────


@activity.defn
async def isolate_host(host: str, tenant_id: str, attack_id: str) -> bool:
    res = await _dispatch("isolate_host", host=host, tenant_id=tenant_id, attack_id=attack_id)
    return bool(res.get("success"))


@activity.defn
async def kill_process(process: str, host: Optional[str], tenant_id: str, attack_id: str) -> bool:
    res = await _dispatch("kill_process", process=process, host=host,
                          tenant_id=tenant_id, attack_id=attack_id)
    return bool(res.get("success"))


@activity.defn
async def reset_credentials(user: str, tenant_id: str, attack_id: str) -> bool:
    res = await _dispatch("reset_credentials", user=user,
                          tenant_id=tenant_id, attack_id=attack_id)
    return bool(res.get("success"))


@activity.defn
async def capture_forensic_snapshot(host: str, tenant_id: str, attack_id: str) -> bool:
    res = await _dispatch("capture_forensic_snapshot", host=host,
                          tenant_id=tenant_id, attack_id=attack_id)
    return bool(res.get("success"))


@activity.defn
async def block_protocol(protocol: str, host: Optional[str], tenant_id: str, attack_id: str) -> bool:
    res = await _dispatch("block_protocol", protocol=protocol, host=host,
                          tenant_id=tenant_id, attack_id=attack_id)
    return bool(res.get("success"))


@activity.defn
async def review_auth_logs(host: str, tenant_id: str, attack_id: str) -> bool:
    res = await _dispatch("review_auth_logs", host=host,
                          tenant_id=tenant_id, attack_id=attack_id)
    return bool(res.get("success"))


# ── enrichment activities (read-only context gathering) ───────────────────────
# These never change state, so the workflow runs them first and automatically.
# In stub mode they log and succeed; a real backend would query TI / asset / IAM.


@activity.defn
async def ioc_lookup(indicator: str, tenant_id: str, attack_id: str) -> bool:
    res = await _dispatch("ioc_lookup", indicator=indicator,
                          tenant_id=tenant_id, attack_id=attack_id)
    return bool(res.get("success"))


@activity.defn
async def asset_context(host: str, tenant_id: str, attack_id: str) -> bool:
    res = await _dispatch("asset_context", host=host,
                          tenant_id=tenant_id, attack_id=attack_id)
    return bool(res.get("success"))


@activity.defn
async def user_context(user: str, tenant_id: str, attack_id: str) -> bool:
    res = await _dispatch("user_context", user=user,
                          tenant_id=tenant_id, attack_id=attack_id)
    return bool(res.get("success"))


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


# ── run bookkeeping (write progress/status back to playbook_runs) ─────────────
# Without these the workflow runs to completion but the playbook_runs row stays
# 'running' with empty completed_actions, so the UI never shows progress or a
# finished run. Each connects to DATABASE_URL per call (short-lived activity).


@activity.defn
async def record_run_progress(run_id: str, action: dict[str, Any]) -> bool:
    dsn = os.getenv("DATABASE_URL")
    if not dsn:
        return False
    try:
        import asyncpg
        conn = await asyncpg.connect(dsn)
        try:
            await conn.execute(
                "UPDATE playbook_runs SET completed_actions = completed_actions || $2::jsonb "
                "WHERE run_id = $1",
                UUID(run_id), json.dumps([action]),
            )
        finally:
            await conn.close()
        return True
    except Exception as e:  # noqa: BLE001
        logger.warning("playbook.record_progress.failed", error=str(e), run_id=run_id)
        return False


@activity.defn
async def finalize_run(run_id: str, status: str) -> bool:
    dsn = os.getenv("DATABASE_URL")
    if not dsn:
        return False
    try:
        import asyncpg
        conn = await asyncpg.connect(dsn)
        try:
            await conn.execute(
                "UPDATE playbook_runs SET status = $2, completed_at = now() WHERE run_id = $1",
                UUID(run_id), status,
            )
        finally:
            await conn.close()
        return True
    except Exception as e:  # noqa: BLE001
        logger.warning("playbook.finalize_run.failed", error=str(e), run_id=run_id)
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
    ioc_lookup,
    asset_context,
    user_context,
    notify_attack_state_complete,
    record_run_progress,
    finalize_run,
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
    # enrichment (read-only)
    "ioc_lookup": ioc_lookup,
    "asset_context": asset_context,
    "user_context": user_context,
}
