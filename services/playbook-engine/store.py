"""asyncpg-backed persistence for playbook_runs."""

from __future__ import annotations
import json
from datetime import datetime, timezone
from typing import Any, Optional
from uuid import UUID

import asyncpg


class PlaybookStore:
    def __init__(self, pool: asyncpg.Pool):
        self.pool = pool

    @classmethod
    async def from_dsn(cls, dsn: str, min_size: int = 2, max_size: int = 10) -> "PlaybookStore":
        pool = await asyncpg.create_pool(dsn, min_size=min_size, max_size=max_size)
        return cls(pool)

    async def close(self) -> None:
        await self.pool.close()

    # ── writes ────────────────────────────────────────────────────────────

    async def create_run(
        self,
        *,
        attack_id: UUID,
        tenant_id: UUID,
        workflow_id: str,
        narrative_id: Optional[str],
        phase_at_trigger: str,
        confidence_at_trigger: float,
        actions: list[dict[str, Any]],
    ) -> UUID:
        sql = """
            INSERT INTO playbook_runs (
                attack_id, tenant_id, workflow_id,
                narrative_id, phase_at_trigger, confidence_at_trigger,
                actions, completed_actions, status
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, '[]'::jsonb, 'running')
            RETURNING run_id
        """
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                sql,
                attack_id,
                tenant_id,
                workflow_id,
                narrative_id,
                phase_at_trigger,
                confidence_at_trigger,
                json.dumps(actions),
            )
        return row["run_id"]

    async def mark_status(
        self,
        run_id: UUID,
        status: str,
        completed_at: Optional[datetime] = None,
    ) -> None:
        if completed_at is None and status in ("completed", "failed"):
            completed_at = datetime.now(timezone.utc)
        sql = """
            UPDATE playbook_runs
               SET status = $2,
                   completed_at = $3
             WHERE run_id = $1
        """
        async with self.pool.acquire() as conn:
            await conn.execute(sql, run_id, status, completed_at)

    async def append_completed_action(
        self,
        run_id: UUID,
        completed_action: dict[str, Any],
    ) -> None:
        """Append the action object onto completed_actions JSONB array."""
        sql = """
            UPDATE playbook_runs
               SET completed_actions = completed_actions || $2::jsonb
             WHERE run_id = $1
        """
        async with self.pool.acquire() as conn:
            await conn.execute(sql, run_id, json.dumps([completed_action]))

    # ── reads ────────────────────────────────────────────────────────────

    async def get_run(self, run_id: UUID, tenant_id: UUID) -> Optional[dict[str, Any]]:
        sql = """
            SELECT * FROM playbook_runs
             WHERE run_id = $1 AND tenant_id = $2
        """
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(sql, run_id, tenant_id)
        return _decode(row) if row else None

    async def get_run_internal(self, run_id: UUID) -> Optional[dict[str, Any]]:
        """Tenant-agnostic. Used by the workflow callback path which only
        knows the run_id from the workflow context.
        """
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow("SELECT * FROM playbook_runs WHERE run_id = $1", run_id)
        return _decode(row) if row else None

    async def list_runs(
        self,
        tenant_id: UUID,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        sql = """
            SELECT * FROM playbook_runs
             WHERE tenant_id = $1
             ORDER BY triggered_at DESC
             LIMIT $2 OFFSET $3
        """
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(sql, tenant_id, limit, offset)
        return [_decode(r) for r in rows]

    async def list_runs_for_attack(
        self,
        attack_id: UUID,
        tenant_id: UUID,
    ) -> list[dict[str, Any]]:
        sql = """
            SELECT * FROM playbook_runs
             WHERE attack_id = $1 AND tenant_id = $2
             ORDER BY triggered_at DESC
        """
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(sql, attack_id, tenant_id)
        return [_decode(r) for r in rows]


def _decode(row: asyncpg.Record) -> dict[str, Any]:
    """asyncpg returns JSONB as str when no codec is registered. Decode it."""
    d = dict(row)
    for k in ("actions", "completed_actions"):
        v = d.get(k)
        if isinstance(v, str):
            try:
                d[k] = json.loads(v)
            except json.JSONDecodeError:
                d[k] = []
        elif v is None:
            d[k] = []
    return d
