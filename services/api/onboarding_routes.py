"""Onboarding endpoints — exclusively for the wizard.

The wizard hits these once at first sign-in. None of them persist
credentials; the SIEM-connection probe is purely a network reachability
test the user can iterate on until it succeeds.
"""

from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime, timezone
from typing import Any, Optional
from uuid import UUID

import httpx
import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from .auth_routes import get_store, require_admin, require_user
from .user_store import UserRow, UserStore

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/onboarding", tags=["onboarding"])
auth_me_router = APIRouter(prefix="/auth", tags=["auth"])


class CheckConnectionRequest(BaseModel):
    siem_type: str  # splunk_es | splunk_core | sentinel | elastic
    # Splunk fields
    host: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    token: Optional[str] = None
    verify_ssl: bool = True
    # Sentinel fields
    tenant_id: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    subscription_id: Optional[str] = None
    resource_group: Optional[str] = None
    workspace_name: Optional[str] = None
    # Elastic fields
    elastic_url: Optional[str] = None
    api_key_id: Optional[str] = None
    api_key_secret: Optional[str] = None


class CheckConnectionResponse(BaseModel):
    connected: bool
    version: Optional[str] = None
    error: Optional[str] = None


@router.post("/check-connection", response_model=CheckConnectionResponse)
async def check_connection(
    req: CheckConnectionRequest,
    user: UserRow = Depends(require_user),
):
    """Best-effort SIEM connectivity probe. Never persists credentials —
    they live in the request body for the duration of the call only."""
    siem = req.siem_type.lower().strip()
    try:
        if siem in ("splunk_es", "splunk_core"):
            return await _probe_splunk(req)
        if siem == "sentinel":
            return await _probe_sentinel(req)
        if siem == "elastic":
            return await _probe_elastic(req)
        raise HTTPException(
            status_code=400,
            detail=f"unknown siem_type '{req.siem_type}' — expected splunk_es | splunk_core | sentinel | elastic",
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.warning("onboarding.check_connection_failed", siem=siem, error=str(e))
        return CheckConnectionResponse(connected=False, error=str(e))


@router.post("/seed-demo")
async def seed_demo(user: UserRow = Depends(require_admin)):
    """Push synthetic CDM events to Kafka so the new tenant sees an
    AttackState within seconds. Admin-only."""
    try:
        from kafka import KafkaProducer  # type: ignore
    except ImportError:
        raise HTTPException(status_code=503, detail="Kafka client unavailable")

    bootstrap = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
    topic = os.getenv("KAFKA_TOPIC_SIGNALS", "vigil.signals.raw")

    try:
        producer = KafkaProducer(
            bootstrap_servers=bootstrap,
            value_serializer=lambda v: json.dumps(v).encode("utf-8"),
            request_timeout_ms=5000,
        )
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Kafka unreachable: {e}")

    events = _demo_events(str(user.tenant_id))
    try:
        for ev in events:
            producer.send(topic, ev)
        producer.flush(timeout=5)
    finally:
        try:
            producer.close(timeout=2)
        except Exception:
            pass

    logger.info("onboarding.seed_demo.published", tenant_id=str(user.tenant_id), count=len(events))
    return {"published": len(events)}


@auth_me_router.patch("/me/onboarding-complete")
async def patch_onboarding_complete(
    user: UserRow = Depends(require_user),
    store: UserStore = Depends(get_store),
):
    await store.mark_onboarding_complete(user.user_id)
    return {"onboarding_complete": True}


# ── probes ────────────────────────────────────────────────────────────────


async def _probe_splunk(req: CheckConnectionRequest) -> CheckConnectionResponse:
    if not req.host:
        return CheckConnectionResponse(connected=False, error="host required")
    headers = {}
    if req.token:
        headers["Authorization"] = f"Bearer {req.token}"
    auth: Optional[tuple[str, str]] = (req.username, req.password) if req.username and req.password else None
    try:
        async with httpx.AsyncClient(timeout=15.0, verify=req.verify_ssl) as client:
            resp = await client.get(
                f"{req.host.rstrip('/')}/services/server/info?output_mode=json",
                headers=headers,
                auth=auth,
            )
            if resp.status_code >= 400:
                return CheckConnectionResponse(
                    connected=False,
                    error=f"Splunk returned {resp.status_code}",
                )
            body = resp.json()
            entry = (body.get("entry") or [{}])[0]
            version = (entry.get("content") or {}).get("version")
            return CheckConnectionResponse(connected=True, version=version)
    except Exception as e:
        return CheckConnectionResponse(connected=False, error=str(e))


async def _probe_sentinel(req: CheckConnectionRequest) -> CheckConnectionResponse:
    required = [req.tenant_id, req.client_id, req.client_secret]
    if not all(required):
        return CheckConnectionResponse(connected=False, error="tenant_id/client_id/client_secret required")
    url = f"https://login.microsoftonline.com/{req.tenant_id}/oauth2/v2.0/token"
    data = {
        "client_id": req.client_id, "client_secret": req.client_secret,
        "grant_type": "client_credentials",
        "scope": "https://api.loganalytics.io/.default",
    }
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(url, data=data)
            if resp.status_code == 200 and resp.json().get("access_token"):
                return CheckConnectionResponse(connected=True, version="azure-ad")
            return CheckConnectionResponse(
                connected=False,
                error=f"AAD returned {resp.status_code}",
            )
    except Exception as e:
        return CheckConnectionResponse(connected=False, error=str(e))


async def _probe_elastic(req: CheckConnectionRequest) -> CheckConnectionResponse:
    if not (req.elastic_url and req.api_key_id and req.api_key_secret):
        return CheckConnectionResponse(connected=False, error="elastic_url/api_key_id/api_key_secret required")
    import base64
    token = base64.b64encode(f"{req.api_key_id}:{req.api_key_secret}".encode()).decode()
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(
                f"{req.elastic_url.rstrip('/')}/",
                headers={"Authorization": f"ApiKey {token}"},
            )
            if resp.status_code == 200:
                version = (resp.json().get("version") or {}).get("number")
                return CheckConnectionResponse(connected=True, version=version)
            return CheckConnectionResponse(
                connected=False,
                error=f"Elastic returned {resp.status_code}",
            )
    except Exception as e:
        return CheckConnectionResponse(connected=False, error=str(e))


def _demo_events(tenant_id: str) -> list[dict[str, Any]]:
    """Emit a small credential-access → lateral-movement chain."""
    now = datetime.now(timezone.utc)
    return [
        {
            "tenant_id": tenant_id,
            "source_event_id": "demo-1",
            "source_siem": "demo",
            "title": "Multiple failed logins (demo)",
            "severity": "high",
            "timestamp": now.isoformat(),
            "rule_name": "Brute Force",
            "detection_id": "D1",
            "user": {"username": "demo-user"},
            "host": {"hostname": "demo-host"},
            "raw_event": {"demo": True},
        },
        {
            "tenant_id": tenant_id,
            "source_event_id": "demo-2",
            "source_siem": "demo",
            "title": "Suspicious lateral SMB (demo)",
            "severity": "high",
            "timestamp": now.isoformat(),
            "rule_name": "SMB Lateral",
            "detection_id": "D3",
            "host": {"hostname": "demo-host-2"},
            "raw_event": {"demo": True},
        },
    ]
