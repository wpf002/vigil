"""
AttackStateStore — asyncpg-backed persistence for AttackState objects.

AttackState is stored as a single JSONB column (full Pydantic serialization).
Indexed columns mirror frequently-filtered fields for query performance.
No ORM — queries are bespoke for the JSONB payload shape.
"""

from __future__ import annotations

import json
from typing import Any, Optional
from uuid import UUID

import asyncpg
import structlog

from .models.attack_state import (
    AttackState,
    AttackStateStatus,
    AttackStateTransition,
    MITRETactic,
    Momentum,
)

logger = structlog.get_logger(__name__)


def _serialize_state(state: AttackState) -> str:
    return state.model_dump_json()


def _deserialize_state(payload: Any) -> AttackState:
    if isinstance(payload, (bytes, bytearray)):
        payload = payload.decode("utf-8")
    if isinstance(payload, str):
        return AttackState.model_validate_json(payload)
    return AttackState.model_validate(payload)


class AttackStateStore:
    """Direct asyncpg access. Caller manages the pool lifecycle."""

    def __init__(self, pool: asyncpg.Pool):
        self.pool = pool

    @classmethod
    async def from_dsn(cls, dsn: str, min_size: int = 2, max_size: int = 10) -> "AttackStateStore":
        pool = await asyncpg.create_pool(dsn, min_size=min_size, max_size=max_size)
        return cls(pool)

    async def close(self) -> None:
        await self.pool.close()

    # ── writes ────────────────────────────────────────────────────────────────

    async def create(self, state: AttackState) -> None:
        sql = """
            INSERT INTO attack_states (
                attack_id, tenant_id, name, status, current_phase,
                confidence, momentum, impact, state, first_seen, last_seen
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10, $11)
        """
        async with self.pool.acquire() as conn:
            await conn.execute(
                sql,
                state.attack_id,
                state.tenant_id,
                state.name,
                state.status.value,
                state.current_phase.value,
                state.confidence,
                state.momentum.value,
                state.impact.value,
                _serialize_state(state),
                state.first_seen,
                state.last_seen,
            )
        logger.info(
            "attack_state.created",
            attack_id=str(state.attack_id),
            tenant_id=state.tenant_id,
            phase=state.current_phase.value,
            confidence=state.confidence,
        )

    async def update(self, state: AttackState) -> None:
        sql = """
            UPDATE attack_states SET
                name = $2,
                status = $3,
                current_phase = $4,
                confidence = $5,
                momentum = $6,
                impact = $7,
                state = $8::jsonb,
                last_seen = $9,
                updated_at = now()
            WHERE attack_id = $1
        """
        async with self.pool.acquire() as conn:
            result = await conn.execute(
                sql,
                state.attack_id,
                state.name,
                state.status.value,
                state.current_phase.value,
                state.confidence,
                state.momentum.value,
                state.impact.value,
                _serialize_state(state),
                state.last_seen,
            )
        if result.endswith("0"):
            raise ValueError(f"AttackState not found: {state.attack_id}")

    async def upsert(self, state: AttackState) -> None:
        sql = """
            INSERT INTO attack_states (
                attack_id, tenant_id, name, status, current_phase,
                confidence, momentum, impact, state, first_seen, last_seen
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10, $11)
            ON CONFLICT (attack_id) DO UPDATE SET
                name = EXCLUDED.name,
                status = EXCLUDED.status,
                current_phase = EXCLUDED.current_phase,
                confidence = EXCLUDED.confidence,
                momentum = EXCLUDED.momentum,
                impact = EXCLUDED.impact,
                state = EXCLUDED.state,
                last_seen = EXCLUDED.last_seen,
                updated_at = now()
        """
        async with self.pool.acquire() as conn:
            await conn.execute(
                sql,
                state.attack_id,
                state.tenant_id,
                state.name,
                state.status.value,
                state.current_phase.value,
                state.confidence,
                state.momentum.value,
                state.impact.value,
                _serialize_state(state),
                state.first_seen,
                state.last_seen,
            )

    async def record_transition(self, transition: AttackStateTransition) -> None:
        sql = """
            INSERT INTO attack_state_transitions (
                transition_id, attack_id, tenant_id,
                previous_phase, new_phase,
                previous_confidence, new_confidence,
                previous_momentum, new_momentum,
                trigger_signal_id, trigger_detection_id,
                is_escalation, transition_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
        """
        async with self.pool.acquire() as conn:
            await conn.execute(
                sql,
                transition.transition_id,
                transition.attack_id,
                transition.tenant_id,
                transition.previous_phase.value if transition.previous_phase else None,
                transition.new_phase.value,
                transition.previous_confidence,
                transition.new_confidence,
                transition.previous_momentum.value,
                transition.new_momentum.value,
                transition.trigger_signal_id,
                transition.trigger_detection_id,
                transition.is_escalation,
                transition.timestamp,
            )

    # ── reads ─────────────────────────────────────────────────────────────────

    async def get_by_id(self, attack_id: UUID, tenant_id: str) -> Optional[AttackState]:
        sql = "SELECT state FROM attack_states WHERE attack_id = $1 AND tenant_id = $2"
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(sql, attack_id, tenant_id)
        return _deserialize_state(row["state"]) if row else None

    async def get_by_id_internal(self, attack_id: UUID) -> Optional[AttackState]:
        """Tenant-agnostic lookup. Use only for internal service callers
        (e.g. the AI engine PATCHing narratives) — never expose to user JWTs.
        """
        sql = "SELECT state FROM attack_states WHERE attack_id = $1"
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(sql, attack_id)
        return _deserialize_state(row["state"]) if row else None

    async def get_active_by_tenant(
        self, tenant_id: str, limit: int = 50, offset: int = 0
    ) -> list[AttackState]:
        sql = """
            SELECT state FROM attack_states
            WHERE tenant_id = $1 AND status = $2
            ORDER BY confidence DESC, last_seen DESC
            LIMIT $3 OFFSET $4
        """
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                sql, tenant_id, AttackStateStatus.ACTIVE.value, limit, offset
            )
        return [_deserialize_state(r["state"]) for r in rows]

    async def get_by_entity(
        self, entity_type: str, entity_value: str, tenant_id: str
    ) -> list[AttackState]:
        """
        entity_type ∈ {host, user, process, credential, cloud_resource}.
        Matches against the corresponding JSONB array on the AttackState.
        Only active states are returned (correlation never re-opens closed states).
        """
        column_map = {
            "host": "hosts",
            "user": "users",
            "process": "processes",
            "credential": "credentials",
            "cloud_resource": "cloud_resources",
        }
        key = column_map.get(entity_type)
        if not key:
            return []
        sql = f"""
            SELECT state FROM attack_states
            WHERE tenant_id = $1
              AND status = $2
              AND state -> '{key}' ? $3
            ORDER BY last_seen DESC
        """
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                sql, tenant_id, AttackStateStatus.ACTIVE.value, entity_value
            )
        return [_deserialize_state(r["state"]) for r in rows]

    async def search(
        self,
        tenant_id: str,
        phase: Optional[MITRETactic] = None,
        min_confidence: Optional[float] = None,
        momentum: Optional[Momentum] = None,
        status: Optional[AttackStateStatus] = AttackStateStatus.ACTIVE,
        limit: int = 50,
        offset: int = 0,
    ) -> list[AttackState]:
        clauses = ["tenant_id = $1"]
        params: list[Any] = [tenant_id]

        if status is not None:
            params.append(status.value)
            clauses.append(f"status = ${len(params)}")
        if phase is not None:
            params.append(phase.value)
            clauses.append(f"current_phase = ${len(params)}")
        if min_confidence is not None:
            params.append(min_confidence)
            clauses.append(f"confidence >= ${len(params)}")
        if momentum is not None:
            params.append(momentum.value)
            clauses.append(f"momentum = ${len(params)}")

        params.append(limit)
        limit_idx = len(params)
        params.append(offset)
        offset_idx = len(params)

        sql = f"""
            SELECT state FROM attack_states
            WHERE {' AND '.join(clauses)}
            ORDER BY confidence DESC, last_seen DESC
            LIMIT ${limit_idx} OFFSET ${offset_idx}
        """
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(sql, *params)
        return [_deserialize_state(r["state"]) for r in rows]

    async def stats_summary(self, tenant_id: str) -> dict[str, Any]:
        sql_phase = """
            SELECT current_phase, COUNT(*) AS n
            FROM attack_states
            WHERE tenant_id = $1 AND status = $2
            GROUP BY current_phase
        """
        sql_momentum = """
            SELECT momentum, COUNT(*) AS n
            FROM attack_states
            WHERE tenant_id = $1 AND status = $2
            GROUP BY momentum
        """
        sql_confidence = """
            SELECT
                COUNT(*) FILTER (WHERE confidence < 0.50) AS low,
                COUNT(*) FILTER (WHERE confidence >= 0.50 AND confidence < 0.70) AS medium,
                COUNT(*) FILTER (WHERE confidence >= 0.70 AND confidence < 0.85) AS high,
                COUNT(*) FILTER (WHERE confidence >= 0.85) AS critical,
                COUNT(*) AS total
            FROM attack_states
            WHERE tenant_id = $1 AND status = $2
        """
        active = AttackStateStatus.ACTIVE.value
        async with self.pool.acquire() as conn:
            phase_rows = await conn.fetch(sql_phase, tenant_id, active)
            momentum_rows = await conn.fetch(sql_momentum, tenant_id, active)
            confidence_row = await conn.fetchrow(sql_confidence, tenant_id, active)

        return {
            "total_active": confidence_row["total"] if confidence_row else 0,
            "phase_breakdown": {r["current_phase"]: r["n"] for r in phase_rows},
            "momentum_breakdown": {r["momentum"]: r["n"] for r in momentum_rows},
            "confidence_distribution": {
                "low": confidence_row["low"] if confidence_row else 0,
                "medium": confidence_row["medium"] if confidence_row else 0,
                "high": confidence_row["high"] if confidence_row else 0,
                "critical": confidence_row["critical"] if confidence_row else 0,
            },
        }
