"""Shared playbook dispatch.

The single place that turns an AttackState into a running response playbook:
select a playbook, render its actions, persist a playbook_runs row, and start
the Temporal workflow. Used by both the Kafka consumer (auto, on escalation)
and the REST API (manual, on-demand) so the two paths can never drift.
"""

from __future__ import annotations

import time
from typing import Any, Optional
from uuid import NAMESPACE_DNS, UUID, uuid4, uuid5

import httpx
import jwt
import structlog
from temporalio.client import Client as TemporalClient

from .config import PlaybookEngineConfig
from .narrative_loader import Narrative, render_actions_for, select_playbook
from .store import PlaybookStore
from .workflows.response_workflow import ResponseWorkflow, ResponseWorkflowInput

logger = structlog.get_logger(__name__)


def coerce_tenant_uuid(tenant_id_str: str) -> UUID:
    """Dev-mode tenants may be free-form strings; coerce deterministically."""
    try:
        return UUID(tenant_id_str)
    except (ValueError, TypeError):
        return uuid5(NAMESPACE_DNS, tenant_id_str)


def _service_token(cfg: PlaybookEngineConfig, tenant_id: str) -> str:
    """Mint a short-lived service JWT scoped to the tenant. ASE requires a real
    bearer token in production (the X-Tenant-Id bypass is dev-only); the shared
    auth_secret lets us authenticate service-to-service without a user session.
    """
    now = int(time.time())
    return jwt.encode(
        {"sub": "playbook-engine", "tenant_id": tenant_id, "role": "admin",
         "iat": now, "exp": now + 120},
        cfg.auth_secret, algorithm="HS256",
    )


async def fetch_attack_state(
    cfg: PlaybookEngineConfig, attack_id: str, tenant_id: str
) -> Optional[dict[str, Any]]:
    url = f"{cfg.attack_state_engine_url.rstrip('/')}/attacks/{attack_id}"
    headers = {
        "Authorization": f"Bearer {_service_token(cfg, tenant_id)}",
        "X-Tenant-Id": tenant_id,  # dev fallback
    }
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(url, headers=headers)
            if resp.status_code != 200:
                return None
            body = resp.json()
            if isinstance(body, dict) and "data" in body:
                return body["data"] if isinstance(body["data"], dict) else None
            return body if isinstance(body, dict) else None
    except Exception as e:
        logger.warning("playbook.fetch_attack_failed", error=str(e))
        return None


async def dispatch_playbook(
    attack_state: dict[str, Any],
    *,
    narratives: list[Narrative],
    store: PlaybookStore,
    temporal_client: TemporalClient,
    cfg: PlaybookEngineConfig,
    trigger: str = "auto",
) -> Optional[dict[str, Any]]:
    """Select, persist, and start a response playbook for an attack.

    Returns the created run's metadata, or None if no playbook matched the
    attack's phase/status. `trigger` ("auto" | "manual") is recorded for
    observability; manual dispatch bypasses the Kafka escalation gate entirely
    (the caller invokes this directly regardless of confidence).
    """
    attack_id = UUID(str(attack_state["attack_id"]))
    tenant_id = coerce_tenant_uuid(str(attack_state["tenant_id"]))

    phase = str(attack_state.get("current_phase") or "")
    confidence = float(attack_state.get("confidence") or 0.0)

    status = "Observed"
    for ph in attack_state.get("phases") or []:
        if isinstance(ph, dict) and str(ph.get("phase")) == phase:
            status = str(ph.get("status") or status)
            break

    detection_ids = [
        e.get("detection_id")
        for e in (attack_state.get("evidence") or [])
        if isinstance(e, dict) and e.get("detection_id")
    ]
    playbook = select_playbook(
        narratives, phase=phase, status=status, confidence=confidence,
        mode=trigger, detection_ids=detection_ids or None,
    )
    if playbook is None:
        logger.info("playbook.no_match", phase=phase, status=status, trigger=trigger)
        return None

    primary_host = next(iter(attack_state.get("hosts") or []), None)
    primary_user = next(iter(attack_state.get("users") or []), None)
    actions = render_actions_for(playbook, primary_host=primary_host, primary_user=primary_user)

    run_id = uuid4()
    workflow_id = f"playbook-{run_id}"

    await store.create_run(
        run_id=run_id,
        attack_id=attack_id,
        tenant_id=tenant_id,
        workflow_id=workflow_id,
        narrative_id=playbook.narrative_id,
        phase_at_trigger=phase,
        confidence_at_trigger=confidence,
        actions=actions,
    )

    await temporal_client.start_workflow(
        ResponseWorkflow.run,
        ResponseWorkflowInput(
            attack_id=str(attack_id),
            tenant_id=str(tenant_id),
            run_id=str(run_id),
            actions=actions,
            attack_state_engine_url=cfg.attack_state_engine_url,
            internal_api_key=cfg.internal_api_key,
        ),
        id=workflow_id,
        task_queue=cfg.temporal_task_queue,
    )
    logger.info(
        "playbook.dispatched",
        run_id=str(run_id), attack_id=str(attack_id),
        narrative_id=playbook.narrative_id, trigger=trigger, action_count=len(actions),
    )
    return {
        "run_id": str(run_id),
        "workflow_id": workflow_id,
        "narrative_id": playbook.narrative_id,
        "phase_at_trigger": phase,
        "trigger": trigger,
        "action_count": len(actions),
    }
