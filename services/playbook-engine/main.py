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
from .narrative_loader import load_narratives
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
    global _store, _temporal_client, _config
    _config = get_config()
    _store = await PlaybookStore.from_dsn(_config.database_url)
    _temporal_client = await _ensure_temporal_client(_config)
    logger.info("playbook_engine.api.started", port=_config.port)
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
