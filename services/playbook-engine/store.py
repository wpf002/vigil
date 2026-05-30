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
        run_id: Optional[UUID] = None,
    ) -> UUID:
        # When the caller supplies run_id (so workflow_id = playbook-{run_id}
        # stays consistent and the value is returned to the client), use it;
        # otherwise let the DB generate one.
        sql = """
            INSERT INTO playbook_runs (
                run_id, attack_id, tenant_id, workflow_id,
                narrative_id, phase_at_trigger, confidence_at_trigger,
                actions, completed_actions, status
            )
            VALUES (COALESCE($1, gen_random_uuid()), $2, $3, $4, $5, $6, $7, $8::jsonb, '[]'::jsonb, 'running')
            RETURNING run_id
        """
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                sql,
                run_id,
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


    # ── playbook_definitions (authored playbooks) ─────────────────────────

    async def create_definition(
        self,
        *,
        tenant_id: UUID,
        name: str,
        actions: list[dict[str, Any]],
        trigger_mode: str = "auto",
        trigger_phase: Optional[str] = None,
        trigger_status: Optional[str] = None,
        min_confidence: float = 0.0,
        trigger_detection_id: Optional[str] = None,
        enabled: bool = True,
        created_by: Optional[UUID] = None,
    ) -> dict[str, Any]:
        sql = """
            INSERT INTO playbook_definitions (
                tenant_id, name, enabled, trigger_mode, trigger_phase,
                trigger_status, min_confidence, trigger_detection_id, actions, created_by)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10)
            RETURNING *
        """
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                sql, tenant_id, name, enabled, trigger_mode, trigger_phase,
                trigger_status, min_confidence, trigger_detection_id,
                json.dumps(actions), created_by,
            )
        return _decode(row)

    async def list_definitions(self, tenant_id: UUID) -> list[dict[str, Any]]:
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT * FROM playbook_definitions WHERE tenant_id=$1 ORDER BY created_at DESC",
                tenant_id,
            )
        return [_decode(r) for r in rows]

    async def list_enabled_definitions(self, tenant_id: UUID) -> list[dict[str, Any]]:
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT * FROM playbook_definitions WHERE tenant_id=$1 AND enabled=TRUE",
                tenant_id,
            )
        return [_decode(r) for r in rows]

    async def get_definition(self, definition_id: UUID, tenant_id: UUID) -> Optional[dict[str, Any]]:
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM playbook_definitions WHERE definition_id=$1 AND tenant_id=$2",
                definition_id, tenant_id,
            )
        return _decode(row) if row else None

    async def update_definition(
        self, definition_id: UUID, tenant_id: UUID, **fields: Any
    ) -> Optional[dict[str, Any]]:
        allowed = {
            "name", "enabled", "trigger_mode", "trigger_phase", "trigger_status",
            "min_confidence", "trigger_detection_id", "actions",
        }
        sets, args = [], []
        for k, v in fields.items():
            if k not in allowed or v is None:
                continue
            args.append(json.dumps(v) if k == "actions" else v)
            cast = "::jsonb" if k == "actions" else ""
            sets.append(f"{k}=${len(args)}{cast}")
        if not sets:
            return await self.get_definition(definition_id, tenant_id)
        sets.append("updated_at=now()")
        args.extend([definition_id, tenant_id])
        sql = (f"UPDATE playbook_definitions SET {', '.join(sets)} "
               f"WHERE definition_id=${len(args)-1} AND tenant_id=${len(args)} RETURNING *")
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(sql, *args)
        return _decode(row) if row else None

    async def delete_definition(self, definition_id: UUID, tenant_id: UUID) -> bool:
        async with self.pool.acquire() as conn:
            res = await conn.execute(
                "DELETE FROM playbook_definitions WHERE definition_id=$1 AND tenant_id=$2",
                definition_id, tenant_id,
            )
        return res.endswith("1")


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
        elif v is None and k in d:
            d[k] = []
    return d
