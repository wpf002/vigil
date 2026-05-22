"""VIGIL Analyst Portal — managed service tooling.

Restricted to roles vigil_analyst and vigil_admin. End-customer roles
(analyst, admin) get 403. SLA breach detection runs as a background task.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Optional
from uuid import UUID

import structlog
from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from .auth import StaffPrincipal, get_staff_principal, require_admin
from .config import AnalystPortalConfig, get_config
from .proxy import AttackStateProxy
from .queue_consumer import QueueConsumer
from .sla_monitor import SLAMonitor
from .store import AnalystPortalStore

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


# ── request bodies ────────────────────────────────────────────────────────────

class AnalystActionBody(BaseModel):
    action_type: str
    action_detail: Optional[dict[str, Any]] = None


class CommentBody(BaseModel):
    comment: str


class SLAConfigBody(BaseModel):
    tenant_id: UUID
    tier: str
    response_minutes: int
    escalation_minutes: int


# ── lifespan / state ──────────────────────────────────────────────────────────

_store: Optional[AnalystPortalStore] = None
_proxy: Optional[AttackStateProxy] = None
_sla_monitor: Optional[SLAMonitor] = None
_consumer: Optional[QueueConsumer] = None
_consumer_task: Optional[asyncio.Task] = None
_config: Optional[AnalystPortalConfig] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _store, _proxy, _sla_monitor, _consumer, _consumer_task, _config
    _config = get_config()
    _store = await AnalystPortalStore.from_dsn(_config.database_url)
    _proxy = AttackStateProxy(_config)

    _sla_monitor = SLAMonitor(_store, _config.sla_monitor_interval_seconds)
    _sla_monitor.start()

    _consumer = QueueConsumer(_config, _store)
    try:
        _consumer.connect()
        _consumer_task = asyncio.create_task(_consumer.run())
    except Exception as e:
        logger.warning("analyst_portal.consumer_unavailable", error=str(e))

    logger.info("analyst_portal.started", port=_config.port)
    try:
        yield
    finally:
        if _consumer is not None:
            _consumer.stop()
            _consumer.disconnect()
        if _consumer_task is not None:
            _consumer_task.cancel()
            try:
                await _consumer_task
            except (asyncio.CancelledError, Exception):
                pass
        if _sla_monitor is not None:
            await _sla_monitor.stop()
        if _store is not None:
            await _store.close()


app = FastAPI(title="VIGIL Analyst Portal", version="0.1.0", lifespan=lifespan)


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


def get_store() -> AnalystPortalStore:
    if _store is None:
        raise HTTPException(status_code=503, detail="Store not initialized")
    return _store


def get_proxy() -> AttackStateProxy:
    if _proxy is None:
        raise HTTPException(status_code=503, detail="Proxy not initialized")
    return _proxy


def _analyst_uuid(principal: StaffPrincipal) -> UUID:
    try:
        return UUID(principal.user_id)
    except (ValueError, TypeError):
        from uuid import NAMESPACE_DNS, uuid5
        return uuid5(NAMESPACE_DNS, principal.user_id)


# ── endpoints ─────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    if _store is None:
        return JSONResponse({"status": "starting"}, status_code=503)
    try:
        async with _store.pool.acquire() as conn:
            await conn.execute("SELECT 1")
        consumer_ok = _consumer is not None and _consumer.is_connected()
        return {
            "status": "ok" if consumer_ok else "degraded",
            "service": "analyst-portal",
            "version": "0.1.0",
            "queue_consumer_connected": consumer_ok,
        }
    except Exception as e:
        return JSONResponse({"status": "degraded", "error": str(e)}, status_code=503)


@app.get("/queue")
async def list_queue(
    principal: StaffPrincipal = Depends(get_staff_principal),
    store: AnalystPortalStore = Depends(get_store),
    tenant_id: Optional[UUID] = Query(None),
    priority: Optional[str] = Query(None),
    assigned_to: Optional[UUID] = Query(None),
    limit: int = Query(100, ge=1, le=500),
):
    rows = await store.list_queue(
        tenant_id=tenant_id,
        priority=priority,
        assigned_to=assigned_to,
        limit=limit,
    )
    return ok([_serialize_queue(r) for r in rows], count=len(rows))


@app.post("/queue/{queue_id}/assign")
async def assign_queue_entry(
    queue_id: UUID,
    target_analyst_id: Optional[UUID] = Query(None),
    principal: StaffPrincipal = Depends(get_staff_principal),
    store: AnalystPortalStore = Depends(get_store),
):
    # Admins can assign to anyone; analysts only to themselves.
    if target_analyst_id and principal.role != "vigil_admin":
        return err("Only vigil_admin can assign to other analysts", code=403)
    assignee = target_analyst_id or _analyst_uuid(principal)

    row = await store.assign_queue_entry(queue_id, assignee)
    if row is None:
        return err("Queue entry not found", code=404)
    return ok(_serialize_queue(row))


@app.post("/queue/{queue_id}/acknowledge")
async def acknowledge_queue_entry(
    queue_id: UUID,
    principal: StaffPrincipal = Depends(get_staff_principal),
    store: AnalystPortalStore = Depends(get_store),
):
    entry = await store.get_queue_entry(queue_id)
    if entry is None:
        return err("Queue entry not found", code=404)

    when = datetime.now(timezone.utc)
    updated = await store.acknowledge_queue_entry(queue_id, when)
    if updated is None:
        return err("Queue entry not found", code=404)

    response_seconds = int((when - entry["escalated_at"]).total_seconds())
    sla_met = when <= entry["sla_deadline"]

    await store.record_action(
        attack_id=entry["attack_id"],
        tenant_id=entry["tenant_id"],
        analyst_id=_analyst_uuid(principal),
        action_type="acknowledged",
        action_detail={"queue_id": str(queue_id)},
        response_time_seconds=response_seconds,
        sla_met=sla_met,
    )
    return ok({**_serialize_queue(updated), "sla_met": sla_met, "response_time_seconds": response_seconds})


@app.post("/queue/{queue_id}/resolve")
async def resolve_queue_entry(
    queue_id: UUID,
    principal: StaffPrincipal = Depends(get_staff_principal),
    store: AnalystPortalStore = Depends(get_store),
):
    entry = await store.get_queue_entry(queue_id)
    if entry is None:
        return err("Queue entry not found", code=404)
    updated = await store.resolve_queue_entry(queue_id)
    if updated is None:
        return err("Queue entry not found", code=404)

    await store.record_action(
        attack_id=entry["attack_id"],
        tenant_id=entry["tenant_id"],
        analyst_id=_analyst_uuid(principal),
        action_type="closed",
        action_detail={"queue_id": str(queue_id)},
    )
    return ok(_serialize_queue(updated))


@app.get("/attacks/{attack_id}")
async def get_attack(
    attack_id: UUID,
    tenant_id: UUID = Query(...),
    principal: StaffPrincipal = Depends(get_staff_principal),
    store: AnalystPortalStore = Depends(get_store),
    proxy: AttackStateProxy = Depends(get_proxy),
):
    state = await proxy.get_attack(str(attack_id), str(tenant_id))
    if state is None:
        return err("Attack not found", code=404)
    actions = await store.list_actions_for_attack(attack_id, tenant_id)
    return ok({
        "state": state,
        "analyst_actions": [_serialize_action(a) for a in actions],
    })


@app.post("/attacks/{attack_id}/actions")
async def record_attack_action(
    attack_id: UUID,
    body: AnalystActionBody,
    tenant_id: UUID = Query(...),
    principal: StaffPrincipal = Depends(get_staff_principal),
    store: AnalystPortalStore = Depends(get_store),
):
    action_id = await store.record_action(
        attack_id=attack_id,
        tenant_id=tenant_id,
        analyst_id=_analyst_uuid(principal),
        action_type=body.action_type,
        action_detail=body.action_detail,
    )
    return ok({"action_id": str(action_id)})


@app.post("/attacks/{attack_id}/comment")
async def comment_on_attack(
    attack_id: UUID,
    body: CommentBody,
    tenant_id: UUID = Query(...),
    principal: StaffPrincipal = Depends(get_staff_principal),
    store: AnalystPortalStore = Depends(get_store),
):
    action_id = await store.record_action(
        attack_id=attack_id,
        tenant_id=tenant_id,
        analyst_id=_analyst_uuid(principal),
        action_type="commented",
        action_detail={"comment": body.comment},
    )
    return ok({"action_id": str(action_id)})


@app.get("/shifts")
async def list_my_shifts(
    principal: StaffPrincipal = Depends(get_staff_principal),
    store: AnalystPortalStore = Depends(get_store),
):
    rows = await store.list_shifts(_analyst_uuid(principal))
    return ok([_serialize_shift(r) for r in rows], count=len(rows))


@app.post("/shifts/start")
async def start_shift(
    principal: StaffPrincipal = Depends(get_staff_principal),
    store: AnalystPortalStore = Depends(get_store),
):
    shift_id = await store.start_shift(_analyst_uuid(principal))
    return ok({"shift_id": str(shift_id), "status": "active"})


@app.post("/shifts/end")
async def end_shift(
    principal: StaffPrincipal = Depends(get_staff_principal),
    store: AnalystPortalStore = Depends(get_store),
):
    row = await store.end_shift(_analyst_uuid(principal))
    if row is None:
        return err("No active shift", code=404)
    return ok(_serialize_shift(row))


@app.get("/sla")
async def list_slas(
    admin: StaffPrincipal = Depends(require_admin),
    store: AnalystPortalStore = Depends(get_store),
):
    rows = await store.list_sla_configs()
    return ok([_serialize_sla(r) for r in rows], count=len(rows))


@app.post("/sla")
async def upsert_sla(
    body: SLAConfigBody,
    admin: StaffPrincipal = Depends(require_admin),
    store: AnalystPortalStore = Depends(get_store),
):
    row = await store.upsert_sla(
        tenant_id=body.tenant_id,
        tier=body.tier,
        response_minutes=body.response_minutes,
        escalation_minutes=body.escalation_minutes,
    )
    return ok(_serialize_sla(row))


@app.get("/stats/summary")
async def stats_summary(
    admin: StaffPrincipal = Depends(require_admin),
    store: AnalystPortalStore = Depends(get_store),
):
    return ok(await store.platform_summary())


@app.get("/stats/analyst/{analyst_id}")
async def stats_analyst(
    analyst_id: UUID,
    principal: StaffPrincipal = Depends(get_staff_principal),
    store: AnalystPortalStore = Depends(get_store),
):
    if principal.role != "vigil_admin" and _analyst_uuid(principal) != analyst_id:
        return err("Cannot view another analyst's stats", code=403)
    return ok(await store.analyst_performance(analyst_id))


# ── serializers ───────────────────────────────────────────────────────────────

def _serialize_queue(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "queue_id": str(row["queue_id"]),
        "attack_id": str(row["attack_id"]),
        "tenant_id": str(row["tenant_id"]),
        "escalated_at": row["escalated_at"].isoformat() if row.get("escalated_at") else None,
        "priority": row["priority"],
        "assigned_to": str(row["assigned_to"]) if row.get("assigned_to") else None,
        "acknowledged_at": row["acknowledged_at"].isoformat() if row.get("acknowledged_at") else None,
        "resolved_at": row["resolved_at"].isoformat() if row.get("resolved_at") else None,
        "sla_deadline": row["sla_deadline"].isoformat() if row.get("sla_deadline") else None,
        "sla_breached": row.get("sla_breached", False),
        "notes": row.get("notes"),
    }


def _serialize_action(row: dict[str, Any]) -> dict[str, Any]:
    detail = row.get("action_detail")
    if isinstance(detail, str):
        import json
        try:
            detail = json.loads(detail)
        except json.JSONDecodeError:
            detail = {}
    return {
        "action_id": str(row["action_id"]),
        "attack_id": str(row["attack_id"]),
        "tenant_id": str(row["tenant_id"]),
        "analyst_id": str(row["analyst_id"]),
        "action_type": row["action_type"],
        "action_detail": detail or {},
        "response_time_seconds": row.get("response_time_seconds"),
        "sla_met": row.get("sla_met"),
        "created_at": row["created_at"].isoformat() if row.get("created_at") else None,
    }


def _serialize_shift(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "shift_id": str(row["shift_id"]),
        "analyst_id": str(row["analyst_id"]),
        "start_time": row["start_time"].isoformat() if row.get("start_time") else None,
        "end_time": row["end_time"].isoformat() if row.get("end_time") else None,
        "status": row["status"],
        "attacks_handled": row.get("attacks_handled", 0),
        "escalations_received": row.get("escalations_received", 0),
        "mean_response_time_seconds": row.get("mean_response_time_seconds"),
    }


def _serialize_sla(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "sla_id": str(row["sla_id"]),
        "tenant_id": str(row["tenant_id"]),
        "tier": row["tier"],
        "response_minutes": row["response_minutes"],
        "escalation_minutes": row["escalation_minutes"],
        "created_at": row["created_at"].isoformat() if row.get("created_at") else None,
    }
