"""VIGIL Reporting Service.

Aggregates metrics from the other services and assembles compliance
evidence packs. Caches per-tenant summaries in Redis with a 5-minute TTL.
"""

from __future__ import annotations

import json
import os
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional
from uuid import UUID

import asyncpg
import jwt
import structlog
from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from .aggregator import Aggregator
from .cache import TenantCache
from .compliance import ComplianceAssembler
from .config import ReportingConfig, get_config
from .pdf_export import render_compliance_pdf, render_executive_pdf
from .pipeline import collect_pipeline_status
from .scheduler import SnapshotScheduler

logger = structlog.get_logger(__name__)
bearer_scheme = HTTPBearer(auto_error=False)


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


# ── auth ──────────────────────────────────────────────────────────────────────


@dataclass
class TenantPrincipal:
    tenant_id: str
    user_id: str
    role: str = "analyst"
    raw_jwt: Optional[str] = None


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={"error": "Unauthorized", "detail": detail},
    )


async def get_principal(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> TenantPrincipal:
    cfg = get_config()
    environment = (os.getenv("ENVIRONMENT") or cfg.environment or "production").lower()

    if credentials is None and environment == "development":
        dev_tenant = request.headers.get("X-Tenant-Id")
        if dev_tenant:
            return TenantPrincipal(tenant_id=dev_tenant, user_id=dev_tenant, role="admin")

    if credentials is None:
        raise _unauthorized("Missing bearer token")

    try:
        payload = jwt.decode(credentials.credentials, cfg.auth_secret, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise _unauthorized("Token expired")
    except jwt.InvalidTokenError:
        raise _unauthorized("Invalid token")

    tenant_id = payload.get("tenant_id")
    user_id = payload.get("sub")
    if not tenant_id or not user_id:
        raise _unauthorized("Token missing tenant_id or sub")
    return TenantPrincipal(
        tenant_id=str(tenant_id), user_id=str(user_id),
        role=str(payload.get("role", "analyst")),
        raw_jwt=credentials.credentials,
    )


# ── lifespan / state ──────────────────────────────────────────────────────────


_pool: Optional[asyncpg.Pool] = None
_aggregator: Optional[Aggregator] = None
_compliance: Optional[ComplianceAssembler] = None
_scheduler: Optional[SnapshotScheduler] = None
_cache: Optional[TenantCache] = None
_redis_client: Any = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _pool, _aggregator, _compliance, _scheduler, _cache, _redis_client
    cfg = get_config()
    _pool = await asyncpg.create_pool(cfg.database_url, min_size=2, max_size=10)
    _aggregator = Aggregator(
        attack_state_engine_url=cfg.attack_state_engine_url,
        detection_engine_url=cfg.detection_engine_url,
        analyst_portal_url=cfg.analyst_portal_url,
        api_url=cfg.api_url,
        internal_api_key=cfg.internal_api_key,
    )
    _compliance = ComplianceAssembler(
        api_url=cfg.api_url,
        attack_state_engine_url=cfg.attack_state_engine_url,
        detection_engine_url=cfg.detection_engine_url,
        analyst_portal_url=cfg.analyst_portal_url,
        internal_api_key=cfg.internal_api_key,
    )
    try:
        import redis.asyncio as redis_aio  # type: ignore
        _redis_client = redis_aio.from_url(cfg.redis_url)
        # Touch the connection so misconfiguration shows up in startup logs.
        await _redis_client.ping()
    except Exception as e:
        logger.warning("reporting.redis_unavailable", error=str(e))
        _redis_client = None
    _cache = TenantCache(_redis_client, cfg.cache_ttl_seconds)
    _scheduler = SnapshotScheduler(
        pool=_pool,
        aggregator=_aggregator,
        hour_utc=cfg.snapshot_hour_utc,
        minute_utc=cfg.snapshot_minute_utc,
    )
    _scheduler.start()
    logger.info("reporting.started", port=cfg.port)
    try:
        yield
    finally:
        if _scheduler is not None:
            await _scheduler.stop()
        if _pool is not None:
            await _pool.close()
        if _redis_client is not None:
            try:
                await _redis_client.close()
            except Exception:
                pass


def create_app() -> FastAPI:
    app = FastAPI(title="VIGIL Reporting", version="0.1.0", lifespan=lifespan)
    cfg = get_config()
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cfg.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/health")
    async def health():
        if _pool is None:
            return JSONResponse({"status": "starting"}, status_code=503)
        try:
            async with _pool.acquire() as conn:
                await conn.execute("SELECT 1")
            return {"status": "ok", "service": "reporting", "version": "0.1.0"}
        except Exception as e:
            return JSONResponse({"status": "degraded", "error": str(e)}, status_code=503)

    @app.get("/pipeline/status")
    async def pipeline_status(_: TenantPrincipal = Depends(get_principal)):
        """Authenticated server-side aggregator for the FE Pipeline page.
        Fans out /health to every VIGIL service over host.docker.internal."""
        return ok(await collect_pipeline_status())

    @app.get("/executive/summary")
    async def executive_summary(principal: TenantPrincipal = Depends(get_principal)):
        tenant = _tenant_uuid(principal)
        cached = await _cache.get(str(tenant), "summary") if _cache else None
        if cached:
            return ok(cached, cached=True)
        data = await _aggregator.executive_summary(tenant, jwt=principal.raw_jwt)
        if _cache:
            await _cache.set(str(tenant), "summary", data)
        return ok(data, cached=False)

    @app.get("/executive/trend")
    async def executive_trend(
        days: int = Query(30, ge=7, le=180),
        principal: TenantPrincipal = Depends(get_principal),
    ):
        if days not in (7, 30, 90):
            return err("days must be 7, 30, or 90", code=400)
        tenant = _tenant_uuid(principal)
        scope = f"trend:{days}"
        cached = await _cache.get(str(tenant), scope) if _cache else None
        if cached:
            return ok(cached, cached=True)
        data = await _aggregator.trend(tenant, days=days, jwt=principal.raw_jwt)
        if _cache:
            await _cache.set(str(tenant), scope, data)
        return ok(data, cached=False)

    @app.get("/compliance/soc2")
    async def compliance_soc2(
        period_days: int = Query(30, ge=1, le=365),
        principal: TenantPrincipal = Depends(get_principal),
    ):
        tenant = _tenant_uuid(principal)
        return ok(await _compliance.soc2(tenant, period_days=period_days, jwt=principal.raw_jwt))

    @app.get("/compliance/pci")
    async def compliance_pci(
        period_days: int = Query(30, ge=1, le=365),
        principal: TenantPrincipal = Depends(get_principal),
    ):
        tenant = _tenant_uuid(principal)
        return ok(await _compliance.pci(tenant, period_days=period_days, jwt=principal.raw_jwt))

    @app.get("/compliance/nist")
    async def compliance_nist(
        period_days: int = Query(30, ge=1, le=365),
        principal: TenantPrincipal = Depends(get_principal),
    ):
        tenant = _tenant_uuid(principal)
        return ok(await _compliance.nist(tenant, period_days=period_days, jwt=principal.raw_jwt))

    @app.get("/compliance/audit-log")
    async def compliance_audit_log(
        days: int = Query(30, ge=1, le=365),
        event_type: Optional[str] = Query(None),
        user_id: Optional[UUID] = Query(None),
        principal: TenantPrincipal = Depends(get_principal),
    ):
        tenant = _tenant_uuid(principal)
        entries = await _compliance.audit_log(
            tenant, days=days, event_type=event_type, user_id=user_id,
            jwt=principal.raw_jwt,
        )
        return ok(entries, count=len(entries))

    @app.get("/reports/export")
    async def reports_export(
        type: str = Query("executive"),
        format: str = Query("pdf"),
        period_days: int = Query(30, ge=1, le=365),
        principal: TenantPrincipal = Depends(get_principal),
    ):
        if format not in ("pdf", "json"):
            return err("format must be 'pdf' or 'json'", code=400)
        tenant = _tenant_uuid(principal)
        report_type = type.lower()
        if report_type == "soc2":
            payload = await _compliance.soc2(tenant, period_days=period_days, jwt=principal.raw_jwt)
        elif report_type == "pci":
            payload = await _compliance.pci(tenant, period_days=period_days, jwt=principal.raw_jwt)
        elif report_type == "nist":
            payload = await _compliance.nist(tenant, period_days=period_days, jwt=principal.raw_jwt)
        elif report_type == "executive":
            summary = await _aggregator.executive_summary(tenant, jwt=principal.raw_jwt)
            trend = await _aggregator.trend(tenant, days=period_days, jwt=principal.raw_jwt)
            payload = {
                "tenant_id": str(tenant),
                "type": "executive",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "summary": summary,
                "trend": trend,
            }
        else:
            return err(f"unknown report type: {type}", code=400)

        date_part = datetime.now(timezone.utc).strftime("%Y%m%d")
        filename = f"vigil-{report_type}-report-{date_part}.{format}"

        if format == "pdf":
            try:
                if report_type == "executive":
                    pdf_bytes = render_executive_pdf(payload)
                else:
                    pdf_bytes = render_compliance_pdf(payload)
            except Exception as e:
                logger.exception("reporting.pdf_render_failed", error=str(e))
                return err(f"PDF render failed: {e}", code=500)
            return StreamingResponse(
                iter([pdf_bytes]),
                media_type="application/pdf",
                headers={"Content-Disposition": f"attachment; filename={filename}"},
            )

        return StreamingResponse(
            iter([json.dumps(payload, indent=2, default=str)]),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )

    return app


def _tenant_uuid(principal: TenantPrincipal) -> UUID:
    try:
        return UUID(principal.tenant_id)
    except (ValueError, TypeError):
        return UUID("00000000-0000-0000-0000-000000000000")


app = create_app()
