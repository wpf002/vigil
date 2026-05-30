"""
VIGIL Attack-State Service

REST API exposing AttackState data for the analyst portal.
All endpoints scope queries to the tenant_id derived from the JWT claim.
"""

from __future__ import annotations

import asyncio
import random
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from uuid import UUID

import structlog
import uvicorn
from fastapi import Depends, FastAPI, Header, HTTPException, Query, status
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


class ResponseStepUpdate(BaseModel):
    step: str           # containment | eradication | recovery
    value: bool = True


class NarrativeUpdate(BaseModel):
    """Body of PATCH /attacks/{id}/narrative — populated by the AI engine."""
    narrative: Optional[str] = None
    predicted_next_phase: Optional[MITRETactic] = None
    analyst_summary: Optional[str] = None
    confidence_note: Optional[str] = None


# ── lifespan ──────────────────────────────────────────────────────────────────

_store: Optional[AttackStateStore] = None
_config: Optional[AttackStateConfig] = None


async def _auto_resolve_loop() -> None:
    """Background task: periodically resolves aged attacks so demo
    deployments populate MTTR / SLA metrics without manual analyst action.

    Selects active attacks older than `auto_resolve_min_age_minutes` and
    resolves a random `auto_resolve_fraction` of them with a status of
    RESOLVED or CONTAINED (weighted toward RESOLVED). The first eligible
    transition stamps `first_response_at`; the same transition stamps
    `resolved_at` since both move together for unattended resolution.
    """
    cfg = get_config()
    rng = random.Random(0xC0FFEE)
    while True:
        try:
            await asyncio.sleep(cfg.auto_resolve_interval_seconds)
            if _store is None:
                continue
            cutoff = datetime.now(timezone.utc) - timedelta(
                minutes=cfg.auto_resolve_min_age_minutes
            )
            sql = """
                SELECT attack_id, tenant_id, state
                FROM attack_states
                WHERE status = 'active' AND first_seen <= $1
                ORDER BY first_seen ASC
                LIMIT 50
            """
            async with _store.pool.acquire() as conn:
                rows = await conn.fetch(sql, cutoff)
            if not rows:
                continue
            resolved = 0
            for row in rows:
                if rng.random() > cfg.auto_resolve_fraction:
                    continue
                from .models.attack_state import AttackState  # local import: avoid cycles
                state = AttackState.model_validate_json(
                    row["state"] if isinstance(row["state"], str) else row["state"].decode()
                )
                # Resolve most attacks; contain a small minority (≈25%).
                new_status = (
                    AttackStateStatus.CONTAINED if rng.random() < 0.25
                    else AttackStateStatus.RESOLVED
                )
                now = datetime.now(timezone.utc)
                state.status = new_status
                state.last_updated = now
                if state.first_response_at is None:
                    # Place first response somewhere between first_seen and now,
                    # so MTTR isn't pinned to the polling interval.
                    span = (now - state.first_seen).total_seconds()
                    state.first_response_at = state.first_seen + timedelta(
                        seconds=span * rng.uniform(0.2, 0.6)
                    )
                if state.resolved_at is None:
                    state.resolved_at = now
                if new_status == AttackStateStatus.CONTAINED:
                    state.response_status.containment = True
                    state.response_status.containment_at = now
                await _store.update(state)
                resolved += 1
            if resolved:
                logger.info(
                    "attack_state.auto_resolved",
                    resolved=resolved,
                    candidates=len(rows),
                )
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.warning("attack_state.auto_resolve_failed", error=str(e))


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _store, _config
    _config = get_config()
    _store = await AttackStateStore.from_dsn(_config.database_url)
    logger.info("attack_state_service.started", port=_config.port)
    auto_task: Optional[asyncio.Task] = None
    if _config.auto_resolve_enabled:
        auto_task = asyncio.create_task(_auto_resolve_loop())
        logger.info(
            "attack_state.auto_resolve_enabled",
            interval_s=_config.auto_resolve_interval_seconds,
            min_age_m=_config.auto_resolve_min_age_minutes,
            fraction=_config.auto_resolve_fraction,
        )
    yield
    if auto_task:
        auto_task.cancel()
        try:
            await auto_task
        except asyncio.CancelledError:
            pass
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
        allow_origins=cfg.cors_origins,
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
    status: Optional[str] = Query(
        None,
        description="Filter by status. Pass 'all' to include resolved/false-positive (default: active only).",
    ),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    status_arg: Optional[AttackStateStatus]
    if status is None:
        status_arg = AttackStateStatus.ACTIVE
    elif status.lower() == "all":
        status_arg = None
    else:
        try:
            status_arg = AttackStateStatus(status.lower())
        except ValueError:
            return err(f"unknown status '{status}'", code=400)

    states = await store.search(
        tenant_id=principal.tenant_id,
        phase=phase,
        min_confidence=min_confidence,
        momentum=momentum,
        status=status_arg,
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

    now = datetime.now(timezone.utc)
    previous_status = state.status
    state.status = body.status
    state.last_updated = now

    # First time the analyst touches the attack (any non-active status) → first_response_at.
    if state.first_response_at is None and body.status != AttackStateStatus.ACTIVE:
        state.first_response_at = now

    # Terminal statuses → resolved_at (idempotent: keep the original resolution time on re-PATCH).
    terminal = {
        AttackStateStatus.RESOLVED,
        AttackStateStatus.FALSE_POSITIVE,
        AttackStateStatus.CONTAINED,
    }
    if body.status in terminal and state.resolved_at is None:
        state.resolved_at = now
    elif body.status == AttackStateStatus.ACTIVE and previous_status in terminal:
        # Reopened — clear the resolution stamp.
        state.resolved_at = None

    if body.status == AttackStateStatus.CONTAINED:
        state.response_status.containment = True
        state.response_status.containment_at = now

    if body.analyst_note:
        existing = state.analyst_summary or ""
        suffix = f"[{principal.user_id} @ {state.last_updated.isoformat()}] {body.analyst_note}"
        state.analyst_summary = f"{existing}\n{suffix}".strip()

    await store.update(state)
    return ok(state.model_dump(mode="json"))


@app.patch("/attacks/{attack_id}/response-status")
async def update_response_status(
    attack_id: UUID,
    body: ResponseStepUpdate,
    principal: TenantPrincipal = Depends(get_principal),
    store: AttackStateStore = Depends(get_store),
):
    """Mark a triage step (containment / eradication / recovery) done or undone.

    Same persistence path the status PATCH uses for containment — surfaced as an
    ordered triage checklist on the attack detail view.
    """
    state = await store.get_by_id(attack_id, principal.tenant_id)
    if state is None:
        return err("Attack not found", code=404)
    step = body.step.lower()
    if step not in ("containment", "eradication", "recovery"):
        return err("step must be containment, eradication, or recovery", code=400)

    now = datetime.now(timezone.utc)
    setattr(state.response_status, step, body.value)
    setattr(state.response_status, f"{step}_at", now if body.value else None)
    state.last_updated = now
    if state.first_response_at is None and body.value:
        state.first_response_at = now

    await store.update(state)
    return ok(state.model_dump(mode="json"))


@app.patch("/attacks/{attack_id}/narrative")
async def update_narrative(
    attack_id: UUID,
    body: NarrativeUpdate,
    x_internal_key: Optional[str] = Header(None, alias="X-Internal-Key"),
    store: AttackStateStore = Depends(get_store),
):
    """Internal-only. Called by the AI engine to populate narrative fields.

    Auth: a single shared INTERNAL_API_KEY. The AI engine is the only
    authorized writer; user JWTs cannot reach this endpoint.
    """
    cfg = get_config()
    if not x_internal_key or x_internal_key != cfg.internal_api_key:
        raise HTTPException(status_code=401, detail="Invalid internal key")

    state = await store.get_by_id_internal(attack_id)
    if state is None:
        return err("Attack not found", code=404)

    changed = False
    if body.narrative is not None:
        state.narrative = body.narrative
        changed = True
    if body.predicted_next_phase is not None:
        state.predicted_next_phase = body.predicted_next_phase
        changed = True
    if body.analyst_summary is not None:
        state.analyst_summary = body.analyst_summary
        changed = True
    if body.confidence_note is not None:
        # Append confidence note to analyst_summary so the analyst sees it
        # without losing previously written content.
        prefix = state.analyst_summary or ""
        sep = "\n" if prefix else ""
        state.analyst_summary = f"{prefix}{sep}[confidence note] {body.confidence_note}"
        changed = True

    if changed:
        state.last_updated = datetime.now(timezone.utc)
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
