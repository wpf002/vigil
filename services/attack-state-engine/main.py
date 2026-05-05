"""
VIGIL Attack-State Service

REST API exposing AttackState data for the analyst portal.
All endpoints scope queries to the tenant_id derived from the JWT claim.
"""

from __future__ import annotations
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Optional
from uuid import UUID

import structlog
import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from .auth import TenantPrincipal, get_principal
from .config import AttackStateConfig, get_config
from .models.attack_state import (
    AttackStateStatus,
    MITRETactic,
    Momentum,
)
from .store import AttackStateStore

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


# ── request models ────────────────────────────────────────────────────────────

class StatusUpdate(BaseModel):
    status: AttackStateStatus
    analyst_note: Optional[str] = None


# ── lifespan ──────────────────────────────────────────────────────────────────

_store: Optional[AttackStateStore] = None
_config: Optional[AttackStateConfig] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _store, _config
    _config = get_config()
    _store = await AttackStateStore.from_dsn(_config.database_url)
    logger.info("attack_state_service.started", port=_config.port)
    yield
    if _store:
        await _store.close()


app = FastAPI(title="VIGIL Attack-State Service", version="0.1.0", lifespan=lifespan)


@app.middleware("http")
async def attach_request_id(request, call_next):
    response = await call_next(request)
    return response


# CORS — set on app init so wildcards in env apply at startup.
def _install_cors(app: FastAPI) -> None:
    cfg = get_config()
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cfg.cors_allow_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )


_install_cors(app)


def get_store() -> AttackStateStore:
    if _store is None:
        raise HTTPException(status_code=503, detail="Store not initialized")
    return _store


# ── endpoints ─────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    if _store is None:
        return JSONResponse({"status": "starting"}, status_code=503)
    try:
        async with _store.pool.acquire() as conn:
            await conn.execute("SELECT 1")
        return {"status": "ok", "service": "attack-state", "version": "0.1.0"}
    except Exception as e:
        return JSONResponse({"status": "degraded", "error": str(e)}, status_code=503)


@app.get("/attacks")
async def list_attacks(
    principal: TenantPrincipal = Depends(get_principal),
    store: AttackStateStore = Depends(get_store),
    phase: Optional[MITRETactic] = Query(None),
    min_confidence: Optional[float] = Query(None, ge=0.0, le=1.0),
    momentum: Optional[Momentum] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    states = await store.search(
        tenant_id=principal.tenant_id,
        phase=phase,
        min_confidence=min_confidence,
        momentum=momentum,
        limit=limit,
        offset=offset,
    )
    return ok(
        [s.model_dump(mode="json") for s in states],
        count=len(states),
        limit=limit,
        offset=offset,
    )


@app.get("/attacks/stats/summary")
async def stats_summary(
    principal: TenantPrincipal = Depends(get_principal),
    store: AttackStateStore = Depends(get_store),
):
    summary = await store.stats_summary(principal.tenant_id)
    return ok(summary)


@app.get("/attacks/{attack_id}")
async def get_attack(
    attack_id: UUID,
    principal: TenantPrincipal = Depends(get_principal),
    store: AttackStateStore = Depends(get_store),
):
    state = await store.get_by_id(attack_id, principal.tenant_id)
    if state is None:
        return err("Attack not found", code=404)
    return ok(state.model_dump(mode="json"))


@app.get("/attacks/{attack_id}/evidence")
async def get_evidence(
    attack_id: UUID,
    principal: TenantPrincipal = Depends(get_principal),
    store: AttackStateStore = Depends(get_store),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    state = await store.get_by_id(attack_id, principal.tenant_id)
    if state is None:
        return err("Attack not found", code=404)
    evidence_sorted = sorted(state.evidence, key=lambda e: e.timestamp)
    page = evidence_sorted[offset : offset + limit]
    return ok(
        [e.model_dump(mode="json") for e in page],
        total=len(evidence_sorted),
        limit=limit,
        offset=offset,
    )


@app.patch("/attacks/{attack_id}/status")
async def update_status(
    attack_id: UUID,
    body: StatusUpdate,
    principal: TenantPrincipal = Depends(get_principal),
    store: AttackStateStore = Depends(get_store),
):
    state = await store.get_by_id(attack_id, principal.tenant_id)
    if state is None:
        return err("Attack not found", code=404)

    state.status = body.status
    if body.status == AttackStateStatus.CONTAINED:
        state.response_status.containment = True
        state.response_status.containment_at = datetime.now(timezone.utc)
    state.last_updated = datetime.now(timezone.utc)

    if body.analyst_note:
        existing = state.analyst_summary or ""
        suffix = f"[{principal.user_id} @ {state.last_updated.isoformat()}] {body.analyst_note}"
        state.analyst_summary = f"{existing}\n{suffix}".strip()

    await store.update(state)
    return ok(state.model_dump(mode="json"))


@app.post("/attacks/{attack_id}/actions/{action_id}/complete")
async def complete_action(
    attack_id: UUID,
    action_id: int,
    principal: TenantPrincipal = Depends(get_principal),
    store: AttackStateStore = Depends(get_store),
):
    # action_id is the zero-based index into recommended_actions.
    state = await store.get_by_id(attack_id, principal.tenant_id)
    if state is None:
        return err("Attack not found", code=404)
    if action_id < 0 or action_id >= len(state.recommended_actions):
        return err("Action not found", code=404)

    action = state.recommended_actions[action_id]
    action.completed = True
    action.completed_at = datetime.now(timezone.utc)
    state.last_updated = action.completed_at

    await store.update(state)
    return ok(action.model_dump(mode="json"))


if __name__ == "__main__":
    cfg = get_config()
    uvicorn.run(
        "services.attack_state_engine.main:app",
        host="0.0.0.0",
        port=cfg.port,
        reload=False,
    )
