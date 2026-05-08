"""asyncpg-backed persistence for analyst-portal tables."""

from __future__ import annotations
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from uuid import UUID

import asyncpg


SLA_TIER_MAP = {
    "critical": "sla_critical_minutes",
    "high": "sla_high_minutes",
    "medium": "sla_medium_minutes",
    "low": "sla_low_minutes",
}


def deadline_for(escalated_at: datetime, response_minutes: int) -> datetime:
    """Compute the SLA deadline for an escalation. Pure function, easy to test."""
    return escalated_at + timedelta(minutes=response_minutes)


class AnalystPortalStore:
    def __init__(self, pool: asyncpg.Pool):
        self.pool = pool

    @classmethod
    async def from_dsn(cls, dsn: str, min_size: int = 2, max_size: int = 10) -> "AnalystPortalStore":
        pool = await asyncpg.create_pool(dsn, min_size=min_size, max_size=max_size)
        return cls(pool)

    async def close(self) -> None:
        await self.pool.close()

    # ── escalation_queue ──────────────────────────────────────────────────

    async def enqueue_escalation(
        self,
        *,
        attack_id: UUID,
        tenant_id: UUID,
        priority: str,
        sla_deadline: datetime,
        escalated_at: Optional[datetime] = None,
        notes: Optional[str] = None,
    ) -> UUID:
        if escalated_at is None:
            escalated_at = datetime.now(timezone.utc)
        sql = """
            INSERT INTO escalation_queue (
                attack_id, tenant_id, escalated_at,
                priority, sla_deadline, notes
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING queue_id
        """
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                sql,
                attack_id,
                tenant_id,
                escalated_at,
                priority,
                sla_deadline,
                notes,
            )
        return row["queue_id"]

    async def list_queue(
        self,
        *,
        tenant_id: Optional[UUID] = None,
        priority: Optional[str] = None,
        assigned_to: Optional[UUID] = None,
        unassigned_only: bool = False,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        clauses = ["resolved_at IS NULL"]
        params: list[Any] = []
        if tenant_id is not None:
            params.append(tenant_id)
            clauses.append(f"tenant_id = ${len(params)}")
        if priority:
            params.append(priority)
            clauses.append(f"priority = ${len(params)}")
        if assigned_to is not None:
            params.append(assigned_to)
            clauses.append(f"assigned_to = ${len(params)}")
        if unassigned_only:
            clauses.append("assigned_to IS NULL")

        params.append(limit)
        sql = f"""
            SELECT * FROM escalation_queue
             WHERE {' AND '.join(clauses)}
             ORDER BY escalated_at ASC
             LIMIT ${len(params)}
        """
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(sql, *params)
        return [dict(r) for r in rows]

    async def get_queue_entry(self, queue_id: UUID) -> Optional[dict[str, Any]]:
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM escalation_queue WHERE queue_id = $1", queue_id
            )
        return dict(row) if row else None

    async def assign_queue_entry(
        self,
        queue_id: UUID,
        analyst_id: UUID,
    ) -> Optional[dict[str, Any]]:
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                UPDATE escalation_queue
                   SET assigned_to = $2
                 WHERE queue_id = $1
                 RETURNING *
                """,
                queue_id,
                analyst_id,
            )
        return dict(row) if row else None

    async def acknowledge_queue_entry(
        self,
        queue_id: UUID,
        when: Optional[datetime] = None,
    ) -> Optional[dict[str, Any]]:
        when = when or datetime.now(timezone.utc)
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                UPDATE escalation_queue
                   SET acknowledged_at = $2
                 WHERE queue_id = $1
                 RETURNING *
                """,
                queue_id,
                when,
            )
        return dict(row) if row else None

    async def resolve_queue_entry(
        self,
        queue_id: UUID,
        when: Optional[datetime] = None,
    ) -> Optional[dict[str, Any]]:
        when = when or datetime.now(timezone.utc)
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                UPDATE escalation_queue
                   SET resolved_at = $2
                 WHERE queue_id = $1
                 RETURNING *
                """,
                queue_id,
                when,
            )
        return dict(row) if row else None

    async def find_breaches(self, now: Optional[datetime] = None) -> list[dict[str, Any]]:
        now = now or datetime.now(timezone.utc)
        sql = """
            SELECT * FROM escalation_queue
             WHERE resolved_at IS NULL
               AND sla_breached = FALSE
               AND sla_deadline < $1
        """
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(sql, now)
        return [dict(r) for r in rows]

    async def mark_breached(self, queue_id: UUID) -> None:
        async with self.pool.acquire() as conn:
            await conn.execute(
                "UPDATE escalation_queue SET sla_breached = TRUE WHERE queue_id = $1",
                queue_id,
            )

    # ── sla_configs ───────────────────────────────────────────────────────

    async def get_sla_for(
        self,
        tenant_id: UUID,
        tier: str,
    ) -> Optional[dict[str, Any]]:
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT * FROM sla_configs
                 WHERE tenant_id = $1 AND tier = $2
                """,
                tenant_id,
                tier,
            )
        return dict(row) if row else None

    async def list_sla_configs(self) -> list[dict[str, Any]]:
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT * FROM sla_configs ORDER BY tenant_id, tier"
            )
        return [dict(r) for r in rows]

    async def upsert_sla(
        self,
        *,
        tenant_id: UUID,
        tier: str,
        response_minutes: int,
        escalation_minutes: int,
    ) -> dict[str, Any]:
        sql = """
            INSERT INTO sla_configs (tenant_id, tier, response_minutes, escalation_minutes)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (tenant_id, tier) DO UPDATE SET
                response_minutes = EXCLUDED.response_minutes,
                escalation_minutes = EXCLUDED.escalation_minutes
            RETURNING *
        """
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(sql, tenant_id, tier, response_minutes, escalation_minutes)
        return dict(row)

    # ── analyst_actions ───────────────────────────────────────────────────

    async def record_action(
        self,
        *,
        attack_id: UUID,
        tenant_id: UUID,
        analyst_id: UUID,
        action_type: str,
        action_detail: Optional[dict[str, Any]] = None,
        response_time_seconds: Optional[int] = None,
        sla_met: Optional[bool] = None,
    ) -> UUID:
        sql = """
            INSERT INTO analyst_actions (
                attack_id, tenant_id, analyst_id,
                action_type, action_detail,
                response_time_seconds, sla_met
            )
            VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7)
            RETURNING action_id
        """
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                sql,
                attack_id,
                tenant_id,
                analyst_id,
                action_type,
                json.dumps(action_detail or {}),
                response_time_seconds,
                sla_met,
            )
        return row["action_id"]

    async def list_actions_for_attack(
        self,
        attack_id: UUID,
        tenant_id: UUID,
    ) -> list[dict[str, Any]]:
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT * FROM analyst_actions
                 WHERE attack_id = $1 AND tenant_id = $2
                 ORDER BY created_at ASC
                """,
                attack_id,
                tenant_id,
            )
        return [dict(r) for r in rows]

    # ── analyst_shifts ────────────────────────────────────────────────────

    async def start_shift(self, analyst_id: UUID, when: Optional[datetime] = None) -> UUID:
        when = when or datetime.now(timezone.utc)
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO analyst_shifts (analyst_id, start_time, status)
                VALUES ($1, $2, 'active')
                RETURNING shift_id
                """,
                analyst_id,
                when,
            )
        return row["shift_id"]

    async def end_shift(
        self,
        analyst_id: UUID,
        when: Optional[datetime] = None,
    ) -> Optional[dict[str, Any]]:
        when = when or datetime.now(timezone.utc)
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                UPDATE analyst_shifts
                   SET end_time = $2, status = 'completed'
                 WHERE analyst_id = $1 AND status = 'active'
                 RETURNING *
                """,
                analyst_id,
                when,
            )
        return dict(row) if row else None

    async def list_shifts(self, analyst_id: UUID, limit: int = 50) -> list[dict[str, Any]]:
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT * FROM analyst_shifts
                 WHERE analyst_id = $1
                 ORDER BY start_time DESC
                 LIMIT $2
                """,
                analyst_id,
                limit,
            )
        return [dict(r) for r in rows]

    # ── stats ─────────────────────────────────────────────────────────────

    async def platform_summary(self) -> dict[str, Any]:
        async with self.pool.acquire() as conn:
            open_q = await conn.fetchval(
                "SELECT COUNT(*) FROM escalation_queue WHERE resolved_at IS NULL"
            )
            breached_q = await conn.fetchval(
                "SELECT COUNT(*) FROM escalation_queue WHERE sla_breached = TRUE AND resolved_at IS NULL"
            )
            active_analysts = await conn.fetchval(
                "SELECT COUNT(*) FROM analyst_shifts WHERE status = 'active'"
            )
            mean_response = await conn.fetchval(
                """
                SELECT AVG(response_time_seconds)
                  FROM analyst_actions
                 WHERE response_time_seconds IS NOT NULL
                   AND created_at > now() - interval '7 days'
                """
            )
        return {
            "open_escalations": int(open_q or 0),
            "breached_slas": int(breached_q or 0),
            "active_analysts": int(active_analysts or 0),
            "mean_response_seconds_7d": float(mean_response) if mean_response is not None else None,
        }

    async def analyst_performance(self, analyst_id: UUID) -> dict[str, Any]:
        async with self.pool.acquire() as conn:
            actions = await conn.fetchval(
                "SELECT COUNT(*) FROM analyst_actions WHERE analyst_id = $1",
                analyst_id,
            )
            sla_met = await conn.fetchval(
                "SELECT COUNT(*) FROM analyst_actions WHERE analyst_id = $1 AND sla_met = TRUE",
                analyst_id,
            )
            mean_response = await conn.fetchval(
                """
                SELECT AVG(response_time_seconds)
                  FROM analyst_actions
                 WHERE analyst_id = $1 AND response_time_seconds IS NOT NULL
                """,
                analyst_id,
            )
            shifts = await conn.fetchval(
                "SELECT COUNT(*) FROM analyst_shifts WHERE analyst_id = $1",
                analyst_id,
            )
        return {
            "analyst_id": str(analyst_id),
            "total_actions": int(actions or 0),
            "sla_met_count": int(sla_met or 0),
            "mean_response_seconds": float(mean_response) if mean_response is not None else None,
            "total_shifts": int(shifts or 0),
        }
