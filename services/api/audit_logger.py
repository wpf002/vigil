"""Audit log helper.

Single async entry point: log_event(...). Inserts a row in audit_log
with optional request-derived ip + user-agent. Failures are swallowed —
if the audit log is unreachable, we don't want to block the user
operation that triggered it. Stale rows must come out of monitoring,
not from a missing entry.
"""

from __future__ import annotations
import json
from typing import Any, Optional
from uuid import UUID

import asyncpg
import structlog
from fastapi import Request

logger = structlog.get_logger(__name__)


async def log_event(
    pool: asyncpg.Pool,
    *,
    tenant_id: Optional[UUID] = None,
    user_id: Optional[UUID] = None,
    event_type: str,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    detail: Optional[dict[str, Any]] = None,
    request: Optional[Request] = None,
) -> None:
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    if request is not None:
        ip_address = (
            (request.headers.get("x-forwarded-for") or "").split(",")[0].strip()
            or (request.client.host if request.client else None)
        )
        user_agent = request.headers.get("user-agent")

    try:
        async with pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO audit_log (
                    tenant_id, user_id, event_type, resource_type,
                    resource_id, ip_address, user_agent, detail
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb)
                """,
                tenant_id,
                user_id,
                event_type,
                resource_type,
                resource_id,
                ip_address,
                user_agent,
                json.dumps(detail or {}),
            )
    except Exception as e:
        # Audit log failures must not abort the calling request — log and
        # surface to monitoring instead.
        logger.warning(
            "audit_log.insert_failed",
            event_type=event_type, error=str(e),
        )


async def list_audit_log(
    pool: asyncpg.Pool,
    *,
    tenant_id: Optional[UUID] = None,
    user_id: Optional[UUID] = None,
    event_type: Optional[str] = None,
    days: int = 30,
    limit: int = 1000,
) -> list[dict[str, Any]]:
    clauses: list[str] = ["created_at >= now() - ($1 || ' days')::interval"]
    params: list[Any] = [str(days)]

    def _next() -> str:
        return f"${len(params) + 1}"

    if tenant_id is not None:
        clauses.append(f"tenant_id = {_next()}")
        params.append(tenant_id)
    if user_id is not None:
        clauses.append(f"user_id = {_next()}")
        params.append(user_id)
    if event_type:
        clauses.append(f"event_type = {_next()}")
        params.append(event_type)

    params.append(limit)
    sql = f"""
        SELECT log_id, tenant_id, user_id, event_type, resource_type,
               resource_id, ip_address, user_agent, detail, created_at
          FROM audit_log
         WHERE {' AND '.join(clauses)}
         ORDER BY created_at DESC
         LIMIT ${len(params)}
    """
    async with pool.acquire() as conn:
        rows = await conn.fetch(sql, *params)
    return [
        {
            "log_id": str(r["log_id"]),
            "tenant_id": str(r["tenant_id"]) if r["tenant_id"] else None,
            "user_id": str(r["user_id"]) if r["user_id"] else None,
            "event_type": r["event_type"],
            "resource_type": r["resource_type"],
            "resource_id": r["resource_id"],
            "ip_address": r["ip_address"],
            "user_agent": r["user_agent"],
            "detail": r["detail"],
            "created_at": r["created_at"].isoformat() if r["created_at"] else None,
        }
        for r in rows
    ]
