"""VIGIL Detection Engine.

Governance & control plane for detections. Tracks versions, signal fires,
and per-detection performance. Coverage report consumed by analyst portal
and frontend.
"""

from __future__ import annotations
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from uuid import UUID

import httpx
import structlog
from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from .auth import TenantPrincipal, get_principal, require_admin
from .config import DetectionEngineConfig, get_config
from .coverage import build_coverage_report
from .marketplace_store import MarketplaceStore, serialize_listing
from .performance import PerformanceAggregator, aggregate_for_detection
from .registry_sync import sync_manifest_to_store
from .store import DetectionStore

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


# ── request/response models ───────────────────────────────────────────────────

class SignalRecordRequest(BaseModel):
    detection_id: str
    tenant_id: UUID
    fired_at: datetime
    attack_id: Optional[UUID] = None
    phase_contributed: Optional[str] = None
    status_contributed: Optional[str] = None
    confidence_contribution: Optional[float] = None


# ── lifespan / state ──────────────────────────────────────────────────────────

_store: Optional[DetectionStore] = None
_market: Optional[MarketplaceStore] = None
_config: Optional[DetectionEngineConfig] = None
_aggregator: Optional[PerformanceAggregator] = None


def _platform_tenant(cfg: DetectionEngineConfig) -> UUID:
    try:
        return UUID(cfg.platform_tenant_id)
    except ValueError:
        return UUID("00000000-0000-0000-0000-000000000000")


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _store, _market, _config, _aggregator
    _config = get_config()
    _store = await DetectionStore.from_dsn(_config.database_url)
    _market = MarketplaceStore(_store.pool)

    compiled_path = Path(_config.detections_compiled_path).resolve()
    yaml_path = Path(_config.detections_yaml_path).resolve()
    platform_tenant = _platform_tenant(_config)

    try:
        await sync_manifest_to_store(
            store=_store,
            compiled_path=compiled_path,
            yaml_path=yaml_path,
            tenant_id=platform_tenant,
        )
    except Exception as e:
        # Sync is best-effort; service can still serve queries against existing
        # rows if the manifest is unreadable.
        logger.warning("detection_engine.startup_sync_failed", error=str(e))

    try:
        await seed_curated_listings(_store, _market, platform_tenant)
    except Exception as e:
        logger.warning("detection_engine.curated_seed_failed", error=str(e))

    _aggregator = PerformanceAggregator(
        store=_store,
        tenant_id=platform_tenant,
        interval_seconds=_config.performance_interval_seconds,
    )
    _aggregator.start()

    logger.info("detection_engine.started", port=_config.port)
    try:
        yield
    finally:
        if _aggregator is not None:
            await _aggregator.stop()
        if _store is not None:
            await _store.close()


app = FastAPI(title="VIGIL Detection Engine", version="0.1.0", lifespan=lifespan)


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


def get_store() -> DetectionStore:
    if _store is None:
        raise HTTPException(status_code=503, detail="Store not initialized")
    return _store


def get_market() -> MarketplaceStore:
    if _market is None:
        raise HTTPException(status_code=503, detail="Marketplace not initialized")
    return _market


async def seed_curated_listings(
    store: DetectionStore,
    market: MarketplaceStore,
    platform_tenant: UUID,
) -> int:
    """Promote each platform-tenant active detection into a curated listing.

    Idempotent: existing listings are refreshed, not duplicated.
    """
    rows = await store.list_active_detections(platform_tenant)
    written = 0
    for r in rows:
        if r.get("tenant_id") != platform_tenant:
            continue
        await market.upsert_listing(
            detection_id=r["detection_id"],
            publisher_tenant_id=platform_tenant,
            name=r["detection_id"],
            description=r.get("notes") or f"VIGIL curated detection — {r.get('att_ck_tactic')}",
            att_ck_tactic=str(r.get("att_ck_tactic") or "unknown"),
            att_ck_technique=str(r.get("att_ck_technique") or "unknown"),
            yaml_content=r.get("yaml_content") or "",
            version=r.get("version") or "1.0.0",
            is_curated=True,
        )
        written += 1
    if written:
        logger.info("detection_engine.curated_listings_seeded", count=written)
    return written


def _tenant_uuid(principal: TenantPrincipal) -> UUID:
    """Tenant IDs from JWT are strings. Coerce safely."""
    try:
        return UUID(principal.tenant_id)
    except (ValueError, TypeError):
        # Dev bypass uses a free-form X-Tenant-Id; fall back to platform tenant.
        return _platform_tenant(get_config())


# ── endpoints ─────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    if _store is None:
        return JSONResponse({"status": "starting"}, status_code=503)
    try:
        async with _store.pool.acquire() as conn:
            await conn.execute("SELECT 1")
        return {"status": "ok", "service": "detection-engine", "version": "0.1.0"}
    except Exception as e:
        return JSONResponse({"status": "degraded", "error": str(e)}, status_code=503)


@app.get("/detections")
async def list_detections(
    principal: TenantPrincipal = Depends(get_principal),
    store: DetectionStore = Depends(get_store),
):
    tenant = _tenant_uuid(principal)
    platform = _platform_tenant(get_config())
    rows = await store.list_active_detections(tenant, platform_tenant_id=platform)
    enriched = []
    for r in rows:
        # Performance is recorded under the *consumer's* tenant — even when
        # the detection version itself is platform-shared, the signals
        # firing on it come from the customer's environment.
        perf = await store.latest_performance(r["detection_id"], tenant)
        if perf is None and r["tenant_id"] != tenant:
            perf = await store.latest_performance(r["detection_id"], r["tenant_id"])
        enriched.append({**_serialize_version(r), "performance": _serialize_performance(perf)})
    return ok(enriched, count=len(enriched))


@app.get("/detections/{detection_id}")
async def get_detection(
    detection_id: str,
    principal: TenantPrincipal = Depends(get_principal),
    store: DetectionStore = Depends(get_store),
):
    tenant = _tenant_uuid(principal)
    platform = _platform_tenant(get_config())
    active = await store.get_active_version(detection_id, tenant, platform_tenant_id=platform)
    if active is None:
        return err("Detection not found", code=404)
    perf = await store.latest_performance(detection_id, tenant)
    if perf is None and active["tenant_id"] != tenant:
        perf = await store.latest_performance(detection_id, active["tenant_id"])
    return ok({**_serialize_version(active), "performance": _serialize_performance(perf)})


@app.get("/detections/{detection_id}/history")
async def get_detection_history(
    detection_id: str,
    principal: TenantPrincipal = Depends(get_principal),
    store: DetectionStore = Depends(get_store),
):
    tenant = _tenant_uuid(principal)
    platform = _platform_tenant(get_config())
    versions = await store.list_versions_for(detection_id, tenant, platform_tenant_id=platform)
    return ok([_serialize_version(v) for v in versions], count=len(versions))


@app.get("/detections/{detection_id}/performance")
async def get_detection_performance(
    detection_id: str,
    days: int = Query(30, ge=1, le=180),
    principal: TenantPrincipal = Depends(get_principal),
    store: DetectionStore = Depends(get_store),
):
    tenant = _tenant_uuid(principal)
    platform = _platform_tenant(get_config())
    active = await store.get_active_version(detection_id, tenant, platform_tenant_id=platform)
    if active is None:
        return err("Detection not found", code=404)

    # Use the consumer's tenant for fires + signals — that's where the
    # detection actually fired in production.
    perf = await store.latest_performance(detection_id, tenant)
    if perf is None and active["tenant_id"] != tenant:
        perf = await store.latest_performance(detection_id, active["tenant_id"])
    trend = await store.daily_fires_trend(detection_id, tenant, days=days)
    signals = await store.list_signals_for(detection_id, tenant, limit=200)
    return ok(
        {
            "detection_id": detection_id,
            "summary": _serialize_performance(perf),
            "trend": trend,
            "signals": [_serialize_signal(s) for s in signals],
        }
    )


@app.patch("/detections/{detection_id}/rollback")
async def rollback_detection(
    detection_id: str,
    principal: TenantPrincipal = Depends(require_admin),
    store: DetectionStore = Depends(get_store),
):
    tenant = _tenant_uuid(principal)
    new_active = await store.rollback_to_previous(detection_id, tenant)
    if new_active is None:
        return err("No prior version to roll back to", code=409)

    cfg = get_config()
    # Best-effort: ask signal-translation to recompile from the now-active YAML.
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            await client.post(
                f"{cfg.signal_translation_url.rstrip('/')}/compile",
                json={
                    "detection_id": detection_id,
                    "yaml": new_active.get("yaml_content"),
                },
            )
    except Exception as e:
        logger.warning("detection_engine.recompile_failed", error=str(e), detection_id=detection_id)

    logger.info(
        "detection_engine.rolled_back",
        detection_id=detection_id,
        new_version=new_active.get("version"),
        actor=principal.user_id,
    )
    return ok(_serialize_version(new_active))


@app.patch("/detections/{detection_id}/signals/{signal_id}/false-positive")
async def mark_false_positive(
    detection_id: str,
    signal_id: UUID,
    principal: TenantPrincipal = Depends(get_principal),
    store: DetectionStore = Depends(get_store),
):
    tenant = _tenant_uuid(principal)
    updated = await store.mark_signal_false_positive(signal_id, tenant)
    if updated is None:
        return err("Signal not found", code=404)
    if updated.get("detection_id") != detection_id:
        return err("Signal does not belong to this detection", code=400)

    # Recompute trailing 30d on the spot so the analyst portal sees the
    # new fp_rate immediately.
    try:
        await aggregate_for_detection(
            store=store,
            detection_id=detection_id,
            tenant_id=tenant,
            window_days=30,
        )
    except Exception as e:
        logger.warning(
            "detection_engine.recompute_failed",
            detection_id=detection_id,
            error=str(e),
        )
    return ok(_serialize_signal(updated))


@app.get("/coverage")
async def coverage(
    principal: TenantPrincipal = Depends(get_principal),
    store: DetectionStore = Depends(get_store),
):
    tenant = _tenant_uuid(principal)
    platform = _platform_tenant(get_config())
    active = await store.list_active_detections(tenant, platform_tenant_id=platform)
    return ok(build_coverage_report(active))


@app.post("/internal/signals/record")
async def record_signal_internal(
    body: SignalRecordRequest,
    x_internal_key: Optional[str] = Header(None, alias="X-Internal-Key"),
    store: DetectionStore = Depends(get_store),
):
    cfg = get_config()
    if not x_internal_key or x_internal_key != cfg.internal_api_key:
        raise HTTPException(status_code=401, detail="Invalid internal key")

    fired_at = body.fired_at
    if fired_at.tzinfo is None:
        fired_at = fired_at.replace(tzinfo=timezone.utc)

    signal_id = await store.record_signal(
        detection_id=body.detection_id,
        tenant_id=body.tenant_id,
        fired_at=fired_at,
        attack_id=body.attack_id,
        phase_contributed=body.phase_contributed,
        status_contributed=body.status_contributed,
        confidence_contribution=body.confidence_contribution,
    )
    return ok({"signal_id": str(signal_id)})


# ── marketplace ───────────────────────────────────────────────────────────────


class PublishRequest(BaseModel):
    detection_id: str
    description: Optional[str] = None


@app.get("/marketplace")
async def marketplace_browse(
    tactic: Optional[str] = Query(None),
    technique: Optional[str] = Query(None),
    is_curated: Optional[bool] = Query(None),
    search: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    market: MarketplaceStore = Depends(get_market),
):
    rows = await market.list_listings(
        tactic=tactic, technique=technique, is_curated=is_curated,
        search=search, limit=limit, offset=offset,
    )
    return ok([serialize_listing(r) for r in rows], count=len(rows))


@app.get("/marketplace/stats")
async def marketplace_stats(market: MarketplaceStore = Depends(get_market)):
    return ok(await market.stats())


@app.get("/marketplace/{listing_id}")
async def marketplace_get(
    listing_id: UUID,
    market: MarketplaceStore = Depends(get_market),
):
    row = await market.get_listing(listing_id)
    if row is None:
        return err("Listing not found", code=404)
    return ok(serialize_listing(row, include_yaml=True))


@app.post("/marketplace/publish")
async def marketplace_publish(
    body: PublishRequest,
    principal: TenantPrincipal = Depends(require_admin),
    store: DetectionStore = Depends(get_store),
    market: MarketplaceStore = Depends(get_market),
):
    tenant = _tenant_uuid(principal)
    platform = _platform_tenant(get_config())
    active = await store.get_active_version(body.detection_id, tenant, platform_tenant_id=platform)
    if active is None:
        return err("Detection not found in your library", code=404)
    if not active.get("yaml_content"):
        return err("Detection has no YAML to publish", code=400)

    listing = await market.upsert_listing(
        detection_id=body.detection_id,
        publisher_tenant_id=tenant,
        name=body.detection_id,
        description=body.description,
        att_ck_tactic=str(active.get("att_ck_tactic") or "unknown"),
        att_ck_technique=str(active.get("att_ck_technique") or "unknown"),
        yaml_content=active.get("yaml_content") or "",
        version=str(active.get("version") or "1.0.0"),
        is_curated=False,
    )
    logger.info(
        "marketplace.published",
        listing_id=str(listing["listing_id"]),
        detection_id=body.detection_id,
        publisher=str(tenant),
    )
    return ok(serialize_listing(listing))


@app.post("/marketplace/{listing_id}/import")
async def marketplace_import(
    listing_id: UUID,
    principal: TenantPrincipal = Depends(get_principal),
    store: DetectionStore = Depends(get_store),
    market: MarketplaceStore = Depends(get_market),
):
    listing = await market.get_listing(listing_id)
    if listing is None or listing.get("status") != "active":
        return err("Listing not available", code=404)

    tenant = _tenant_uuid(principal)
    cfg = get_config()

    compiled_spl: Optional[str] = None
    compiled_kql: Optional[str] = None
    compiled_eql: Optional[str] = None
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                f"{cfg.signal_translation_url.rstrip('/')}/compile",
                json={
                    "detection_id": listing["detection_id"],
                    "yaml": listing["yaml_content"],
                },
            )
            if resp.status_code < 400:
                payload = resp.json()
                # The compiler returns either {data: {...}} or the inner dict directly.
                inner = payload.get("data") if isinstance(payload, dict) and "data" in payload else payload
                if isinstance(inner, dict):
                    compiled_spl = inner.get("compiled_spl") or inner.get("spl")
                    compiled_kql = inner.get("compiled_kql") or inner.get("kql")
                    compiled_eql = inner.get("compiled_eql") or inner.get("eql")
    except Exception as e:
        logger.warning("marketplace.compile_failed", error=str(e))

    await store.upsert_version(
        detection_id=listing["detection_id"],
        version=str(listing["version"]),
        yaml_content=listing["yaml_content"],
        compiled_spl=compiled_spl,
        compiled_kql=compiled_kql,
        compiled_eql=compiled_eql,
        att_ck_tactic=listing["att_ck_tactic"],
        att_ck_technique=listing["att_ck_technique"],
        state_impact={},
        tenant_id=tenant,
        notes=f"Imported from marketplace listing {listing_id}",
    )

    import_row = await market.record_import(
        listing_id=listing_id,
        importing_tenant_id=tenant,
        local_detection_id=listing["detection_id"],
    )
    refreshed = await market.get_listing(listing_id)
    return ok(
        {
            "listing": serialize_listing(refreshed) if refreshed else None,
            "import_id": str(import_row["import_id"]),
            "local_detection_id": import_row.get("local_detection_id"),
        }
    )


@app.delete("/marketplace/{listing_id}")
async def marketplace_withdraw(
    listing_id: UUID,
    principal: TenantPrincipal = Depends(require_admin),
    market: MarketplaceStore = Depends(get_market),
):
    tenant = _tenant_uuid(principal)
    row = await market.withdraw_listing(listing_id=listing_id, publisher_tenant_id=tenant)
    if row is None:
        return err("Listing not found or not owned by tenant", code=404)
    return ok(serialize_listing(row))


# ── serializers ───────────────────────────────────────────────────────────────

def _serialize_version(row: dict[str, Any]) -> dict[str, Any]:
    state_impact = row.get("state_impact")
    if isinstance(state_impact, str):
        # asyncpg returns JSONB as str when no codec is registered.
        import json
        try:
            state_impact = json.loads(state_impact)
        except json.JSONDecodeError:
            state_impact = {}
    return {
        "version_id": str(row["version_id"]),
        "detection_id": row["detection_id"],
        "version": row["version"],
        "att_ck_tactic": row["att_ck_tactic"],
        "att_ck_technique": row["att_ck_technique"],
        "state_impact": state_impact or {},
        "status": row["status"],
        "deployed_at": row["deployed_at"].isoformat() if row.get("deployed_at") else None,
        "deployed_by": str(row["deployed_by"]) if row.get("deployed_by") else None,
        "tenant_id": str(row["tenant_id"]),
        "notes": row.get("notes"),
        "yaml_content": row.get("yaml_content"),
        "compiled_spl": row.get("compiled_spl"),
        "compiled_kql": row.get("compiled_kql"),
        "compiled_eql": row.get("compiled_eql"),
    }


def _serialize_performance(row: Optional[dict[str, Any]]) -> Optional[dict[str, Any]]:
    if row is None:
        return None
    return {
        "perf_id": str(row["perf_id"]),
        "detection_id": row["detection_id"],
        "tenant_id": str(row["tenant_id"]),
        "period_start": row["period_start"].isoformat() if row.get("period_start") else None,
        "period_end": row["period_end"].isoformat() if row.get("period_end") else None,
        "total_fires": row["total_fires"],
        "false_positives": row["false_positives"],
        "true_positives": row["true_positives"],
        "escalations": row["escalations"],
        "fp_rate": row["fp_rate"],
        "avg_confidence": row["avg_confidence"],
        "computed_at": row["computed_at"].isoformat() if row.get("computed_at") else None,
    }


def _serialize_signal(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "signal_id": str(row["signal_id"]),
        "detection_id": row["detection_id"],
        "tenant_id": str(row["tenant_id"]),
        "fired_at": row["fired_at"].isoformat() if row.get("fired_at") else None,
        "attack_id": str(row["attack_id"]) if row.get("attack_id") else None,
        "phase_contributed": row.get("phase_contributed"),
        "status_contributed": row.get("status_contributed"),
        "confidence_contribution": row.get("confidence_contribution"),
        "was_false_positive": row.get("was_false_positive", False),
        "closed_as": row.get("closed_as"),
    }
