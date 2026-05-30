"""VIGIL Playbook Engine — FastAPI app.

Read endpoints proxy from playbook_runs. Write endpoints (resume/abort)
fan signals into the Temporal cluster. The Temporal worker that hosts
the workflow code itself runs alongside this app — see run.py.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from uuid import UUID

import structlog
from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from temporalio.client import Client as TemporalClient

from .auth import TenantPrincipal, get_principal
from .config import PlaybookEngineConfig, get_config
from .dispatcher import dispatch_playbook, fetch_attack_state
from .narrative_loader import Narrative, classify_kind, load_narratives
from .store import PlaybookStore

logger = structlog.get_logger(__name__)


# ── envelope ──────────────────────────────────────────────────────────────────

class Envelope(BaseModel):
    data: Any = None
    meta: dict[str, Any] = Field(default_factory=dict)
    error: Optional[str] = None


def ok(data: Any, **meta) -> dict:
    return Envelope(data=data, meta=meta).model_dump(mode="json")


def err(message: str, code: int = 400) -> JSONResponse:
    return JSONResponse(
        status_code=code,
        content=Envelope(error=message).model_dump(mode="json"),
    )


# ── lifespan / state ──────────────────────────────────────────────────────────

_store: Optional[PlaybookStore] = None
_temporal_client: Optional[TemporalClient] = None
_config: Optional[PlaybookEngineConfig] = None
_narratives: list[Narrative] = []


async def _ensure_temporal_client(cfg: PlaybookEngineConfig) -> Optional[TemporalClient]:
    """Best-effort connect. Returns None if Temporal is unreachable; the
    REST surface stays available for read-only queries.
    """
    try:
        return await TemporalClient.connect(cfg.temporal_host, namespace=cfg.temporal_namespace)
    except Exception as e:
        logger.warning("playbook_engine.temporal_unavailable", error=str(e))
        return None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _store, _temporal_client, _config, _narratives
    _config = get_config()
    _store = await PlaybookStore.from_dsn(_config.database_url)
    _temporal_client = await _ensure_temporal_client(_config)
    _narratives = load_narratives(Path(_config.narratives_path))
    logger.info(
        "playbook_engine.api.started", port=_config.port, narratives=len(_narratives)
    )
    try:
        yield
    finally:
        if _store is not None:
            await _store.close()


app = FastAPI(title="VIGIL Playbook Engine", version="0.1.0", lifespan=lifespan)


def _install_cors(app: FastAPI) -> None:
    cfg = get_config()
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cfg.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )


_install_cors(app)


def get_store() -> PlaybookStore:
    if _store is None:
        raise HTTPException(status_code=503, detail="Store not initialized")
    return _store


def _tenant_uuid(principal: TenantPrincipal) -> UUID:
    try:
        return UUID(principal.tenant_id)
    except (ValueError, TypeError):
        from uuid import NAMESPACE_DNS, uuid5
        return uuid5(NAMESPACE_DNS, principal.tenant_id)


# ── endpoints ─────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    if _store is None:
        return JSONResponse({"status": "starting"}, status_code=503)
    try:
        async with _store.pool.acquire() as conn:
            await conn.execute("SELECT 1")
        return {
            "status": "ok",
            "service": "playbook-engine",
            "version": "0.1.0",
            "temporal_connected": _temporal_client is not None,
        }
    except Exception as e:
        return JSONResponse({"status": "degraded", "error": str(e)}, status_code=503)


@app.get("/playbooks")
async def list_playbooks(
    principal: TenantPrincipal = Depends(get_principal),
    store: PlaybookStore = Depends(get_store),
    limit: int = 100,
    offset: int = 0,
):
    tenant = _tenant_uuid(principal)
    runs = await store.list_runs(tenant, limit=limit, offset=offset)
    return ok([_serialize_run(r) for r in runs], count=len(runs))


@app.get("/playbooks/{run_id}")
async def get_playbook(
    run_id: UUID,
    principal: TenantPrincipal = Depends(get_principal),
    store: PlaybookStore = Depends(get_store),
):
    tenant = _tenant_uuid(principal)
    run = await store.get_run(run_id, tenant)
    if run is None:
        return err("Run not found", code=404)
    return ok(_serialize_run(run))


@app.get("/playbooks/attack/{attack_id}")
async def get_playbooks_for_attack(
    attack_id: UUID,
    principal: TenantPrincipal = Depends(get_principal),
    store: PlaybookStore = Depends(get_store),
):
    tenant = _tenant_uuid(principal)
    runs = await store.list_runs_for_attack(attack_id, tenant)
    return ok([_serialize_run(r) for r in runs], count=len(runs))


@app.post("/playbooks/{run_id}/resume")
async def resume_playbook(
    run_id: UUID,
    principal: TenantPrincipal = Depends(get_principal),
    store: PlaybookStore = Depends(get_store),
):
    tenant = _tenant_uuid(principal)
    run = await store.get_run(run_id, tenant)
    if run is None:
        return err("Run not found", code=404)
    if _temporal_client is None:
        return err("Temporal unavailable", code=503)

    try:
        handle = _temporal_client.get_workflow_handle(run["workflow_id"])
        await handle.signal("resume")
    except Exception as e:
        logger.warning("playbook_engine.resume_failed", error=str(e), run_id=str(run_id))
        return err(f"Resume signal failed: {e}", code=502)

    await store.mark_status(run_id, "running")
    return ok({"run_id": str(run_id), "status": "running"})


@app.post("/playbooks/{run_id}/abort")
async def abort_playbook(
    run_id: UUID,
    principal: TenantPrincipal = Depends(get_principal),
    store: PlaybookStore = Depends(get_store),
):
    tenant = _tenant_uuid(principal)
    run = await store.get_run(run_id, tenant)
    if run is None:
        return err("Run not found", code=404)
    if _temporal_client is None:
        return err("Temporal unavailable", code=503)

    try:
        handle = _temporal_client.get_workflow_handle(run["workflow_id"])
        await handle.signal("abort")
    except Exception as e:
        logger.warning("playbook_engine.abort_failed", error=str(e), run_id=str(run_id))
        return err(f"Abort signal failed: {e}", code=502)

    await store.mark_status(run_id, "failed", completed_at=datetime.now(timezone.utc))
    return ok({"run_id": str(run_id), "status": "failed"})


class RunPlaybookRequest(BaseModel):
    attack_id: UUID


@app.post("/playbooks/run")
async def run_playbook(
    body: RunPlaybookRequest,
    principal: TenantPrincipal = Depends(get_principal),
    store: PlaybookStore = Depends(get_store),
):
    """Manually trigger a response playbook for an attack — on demand, from the
    Actions UI, regardless of confidence (no escalation gate). Selects, persists,
    and starts the same workflow the auto (Kafka) path uses.
    """
    if _temporal_client is None:
        return err("Temporal unavailable", code=503)
    if _config is None:
        return err("Service not initialized", code=503)

    attack_state = await fetch_attack_state(_config, str(body.attack_id), principal.tenant_id)
    if attack_state is None:
        return err("Attack not found", code=404)

    result = await dispatch_playbook(
        attack_state,
        narratives=_narratives,
        store=store,
        temporal_client=_temporal_client,
        cfg=_config,
        trigger="manual",
    )
    if result is None:
        return err("No playbook matches this attack's current phase/status", code=422)
    return ok(result)


# ── playbook definitions (build-a-playbook) ───────────────────────────────────

class ActionInput(BaseModel):
    action_type: str
    target: str = "affected_host"
    kind: Optional[str] = None  # inferred from action_type when omitted
    priority: str = "immediate"  # immediate | follow_up
    automated: bool = False
    description: str = ""


class PlaybookDefinitionInput(BaseModel):
    name: str
    actions: list[ActionInput] = Field(default_factory=list)
    trigger_mode: str = "auto"
    trigger_phase: Optional[str] = None
    trigger_status: Optional[str] = None
    min_confidence: float = 0.0
    trigger_detection_id: Optional[str] = None
    enabled: bool = True


class PlaybookDefinitionUpdate(BaseModel):
    name: Optional[str] = None
    actions: Optional[list[ActionInput]] = None
    trigger_mode: Optional[str] = None
    trigger_phase: Optional[str] = None
    trigger_status: Optional[str] = None
    min_confidence: Optional[float] = None
    trigger_detection_id: Optional[str] = None
    enabled: Optional[bool] = None


def _require_admin(principal: TenantPrincipal) -> None:
    if principal.role != "admin":
        raise HTTPException(status_code=403, detail="admin role required")


def _normalize_action(a: ActionInput) -> dict[str, Any]:
    return {
        "action_type": a.action_type,
        "target": a.target,
        "kind": a.kind or classify_kind(a.action_type),
        "priority": a.priority,
        "automated": a.automated,
        "description": a.description,
    }


def _created_by_uuid(principal: TenantPrincipal) -> Optional[UUID]:
    try:
        return UUID(principal.user_id)
    except (ValueError, TypeError):
        return None


@app.get("/playbook-definitions")
async def list_playbook_definitions(
    principal: TenantPrincipal = Depends(get_principal),
    store: PlaybookStore = Depends(get_store),
):
    tenant = _tenant_uuid(principal)
    defs = await store.list_definitions(tenant)
    return ok([_serialize_definition(d) for d in defs], count=len(defs))


@app.post("/playbook-definitions")
async def create_playbook_definition(
    body: PlaybookDefinitionInput,
    principal: TenantPrincipal = Depends(get_principal),
    store: PlaybookStore = Depends(get_store),
):
    _require_admin(principal)
    tenant = _tenant_uuid(principal)
    d = await store.create_definition(
        tenant_id=tenant,
        name=body.name,
        actions=[_normalize_action(a) for a in body.actions],
        trigger_mode=body.trigger_mode,
        trigger_phase=body.trigger_phase,
        trigger_status=body.trigger_status,
        min_confidence=body.min_confidence,
        trigger_detection_id=body.trigger_detection_id,
        enabled=body.enabled,
        created_by=_created_by_uuid(principal),
    )
    return ok(_serialize_definition(d))


@app.get("/playbook-definitions/{definition_id}")
async def get_playbook_definition(
    definition_id: UUID,
    principal: TenantPrincipal = Depends(get_principal),
    store: PlaybookStore = Depends(get_store),
):
    d = await store.get_definition(definition_id, _tenant_uuid(principal))
    if d is None:
        return err("Definition not found", code=404)
    return ok(_serialize_definition(d))


@app.patch("/playbook-definitions/{definition_id}")
async def update_playbook_definition(
    definition_id: UUID,
    body: PlaybookDefinitionUpdate,
    principal: TenantPrincipal = Depends(get_principal),
    store: PlaybookStore = Depends(get_store),
):
    _require_admin(principal)
    tenant = _tenant_uuid(principal)
    fields = body.model_dump(exclude_none=True)
    if body.actions is not None:
        fields["actions"] = [_normalize_action(a) for a in body.actions]
    d = await store.update_definition(definition_id, tenant, **fields)
    if d is None:
        return err("Definition not found", code=404)
    return ok(_serialize_definition(d))


@app.delete("/playbook-definitions/{definition_id}")
async def delete_playbook_definition(
    definition_id: UUID,
    principal: TenantPrincipal = Depends(get_principal),
    store: PlaybookStore = Depends(get_store),
):
    _require_admin(principal)
    deleted = await store.delete_definition(definition_id, _tenant_uuid(principal))
    if not deleted:
        return err("Definition not found", code=404)
    return ok({"definition_id": str(definition_id), "deleted": True})


def _serialize_definition(d: dict[str, Any]) -> dict[str, Any]:
    return {
        "definition_id": str(d["definition_id"]),
        "tenant_id": str(d["tenant_id"]),
        "name": d["name"],
        "enabled": d["enabled"],
        "trigger_mode": d["trigger_mode"],
        "trigger_phase": d.get("trigger_phase"),
        "trigger_status": d.get("trigger_status"),
        "min_confidence": d["min_confidence"],
        "trigger_detection_id": d.get("trigger_detection_id"),
        "actions": d.get("actions") or [],
        "created_at": d["created_at"].isoformat() if d.get("created_at") else None,
        "updated_at": d["updated_at"].isoformat() if d.get("updated_at") else None,
    }


@app.get("/narratives")
async def list_narratives_endpoint(
    principal: TenantPrincipal = Depends(get_principal),
):
    cfg = get_config()
    nars = load_narratives(Path(cfg.narratives_path))
    return ok(
        [
            {
                "narrative_id": n.narrative_id,
                "name": n.name,
                "phases": n.phases,
                "playbooks": [
                    {
                        "playbook_name": pb.playbook_name,
                        "trigger": pb.trigger,
                        "immediate_count": len(pb.immediate),
                        "follow_up_count": len(pb.follow_up),
                    }
                    for pb in n.playbooks
                ],
            }
            for n in nars
        ],
        count=len(nars),
    )


# ── serializers ───────────────────────────────────────────────────────────────

def _serialize_run(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "run_id": str(row["run_id"]),
        "attack_id": str(row["attack_id"]),
        "tenant_id": str(row["tenant_id"]),
        "workflow_id": row["workflow_id"],
        "narrative_id": row.get("narrative_id"),
        "triggered_at": row["triggered_at"].isoformat() if row.get("triggered_at") else None,
        "status": row["status"],
        "phase_at_trigger": row["phase_at_trigger"],
        "confidence_at_trigger": row["confidence_at_trigger"],
        "completed_at": row["completed_at"].isoformat() if row.get("completed_at") else None,
        "actions": row.get("actions") or [],
        "completed_actions": row.get("completed_actions") or [],
    }
