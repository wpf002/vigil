"""asyncpg-backed persistence for the detection engine.

Owns four tables:
  detection_versions      Version history for each detection_id, per tenant.
  detection_signals       Append-only fire log; one row per EvidenceItem.
  detection_performance   Rolled-up windows (7d, 30d) computed hourly.

All queries are tenant-scoped. The internal /signals/record endpoint is
the only writer for detection_signals.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from uuid import UUID

import asyncpg
import structlog

logger = structlog.get_logger(__name__)


class DetectionStore:
    def __init__(self, pool: asyncpg.Pool):
        self.pool = pool

    @classmethod
    async def from_dsn(cls, dsn: str, min_size: int = 2, max_size: int = 10) -> "DetectionStore":
        pool = await asyncpg.create_pool(dsn, min_size=min_size, max_size=max_size)
        return cls(pool)

    async def close(self) -> None:
        await self.pool.close()

    # ── detection_versions ────────────────────────────────────────────────

    async def upsert_version(
        self,
        *,
        detection_id: str,
        version: str,
        yaml_content: str,
        compiled_spl: Optional[str],
        compiled_kql: Optional[str],
        compiled_eql: Optional[str],
        att_ck_tactic: str,
        att_ck_technique: str,
        state_impact: dict[str, Any],
        tenant_id: UUID,
        deployed_by: Optional[UUID] = None,
        notes: Optional[str] = None,
    ) -> UUID:
        """Insert a new active version, deactivating any prior active row.

        Returns the new version_id.
        """
        sql_deactivate = """
            UPDATE detection_versions
               SET status = 'deprecated'
             WHERE detection_id = $1 AND tenant_id = $2 AND status = 'active'
        """
        sql_insert = """
            INSERT INTO detection_versions (
                detection_id, version, yaml_content,
                compiled_spl, compiled_kql, compiled_eql,
                att_ck_tactic, att_ck_technique, state_impact,
                status, deployed_by, tenant_id, notes
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, 'active', $10, $11, $12)
            RETURNING version_id
        """
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                await conn.execute(sql_deactivate, detection_id, tenant_id)
                row = await conn.fetchrow(
                    sql_insert,
                    detection_id,
                    version,
                    yaml_content,
                    compiled_spl,
                    compiled_kql,
                    compiled_eql,
                    att_ck_tactic,
                    att_ck_technique,
                    json.dumps(state_impact),
                    deployed_by,
                    tenant_id,
                    notes,
                )
        return row["version_id"]

    async def delete_detection(self, detection_id: str, tenant_id: UUID) -> int:
        """Delete all of a tenant's versions for a detection. Returns rows removed."""
        async with self.pool.acquire() as conn:
            res = await conn.execute(
                "DELETE FROM detection_versions WHERE detection_id=$1 AND tenant_id=$2",
                detection_id, tenant_id,
            )
        try:
            return int(res.split()[-1])
        except (ValueError, IndexError):
            return 0

    async def get_active_version(
        self,
        detection_id: str,
        tenant_id: UUID,
        platform_tenant_id: Optional[UUID] = None,
    ) -> Optional[dict[str, Any]]:
        """Active version for detection_id. Prefers a tenant override over
        the platform-shared row when both exist.
        """
        params: list[Any] = [detection_id, tenant_id]
        if platform_tenant_id is not None and platform_tenant_id != tenant_id:
            params.append(platform_tenant_id)
            tenant_filter = "tenant_id IN ($2, $3)"
            preference_order = "CASE WHEN tenant_id = $2 THEN 0 ELSE 1 END, deployed_at DESC"
        else:
            tenant_filter = "tenant_id = $2"
            preference_order = "deployed_at DESC"
        sql = f"""
            SELECT * FROM detection_versions
             WHERE detection_id = $1 AND {tenant_filter} AND status = 'active'
             ORDER BY {preference_order}
             LIMIT 1
        """
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(sql, *params)
        return dict(row) if row else None

    async def list_active_detections(
        self,
        tenant_id: UUID,
        platform_tenant_id: Optional[UUID] = None,
    ) -> list[dict[str, Any]]:
        """All active detections visible to this tenant.

        Returns the union of the tenant's own active rows and the platform
        tenant's shared library, with tenant overrides winning when a
        detection_id appears in both.
        """
        params: list[Any] = [tenant_id]
        if platform_tenant_id is not None and platform_tenant_id != tenant_id:
            params.append(platform_tenant_id)
            tenant_filter = "tenant_id IN ($1, $2)"
            preference_expr = "CASE WHEN tenant_id = $1 THEN 0 ELSE 1 END"
        else:
            tenant_filter = "tenant_id = $1"
            preference_expr = "0"
        sql = f"""
            WITH ranked AS (
                SELECT *,
                       ROW_NUMBER() OVER (
                           PARTITION BY detection_id
                           ORDER BY {preference_expr}, deployed_at DESC
                       ) AS rn
                  FROM detection_versions
                 WHERE {tenant_filter} AND status = 'active'
            )
            SELECT * FROM ranked WHERE rn = 1 ORDER BY detection_id ASC
        """
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(sql, *params)
        return [dict(r) for r in rows]

    async def refresh_active_artifacts(
        self,
        *,
        detection_id: str,
        tenant_id: UUID,
        yaml_content: str,
        compiled_spl: Optional[str],
        compiled_kql: Optional[str],
        compiled_eql: Optional[str],
        notes: Optional[str] = None,
    ) -> None:
        """In-place refresh of the compiled artifacts on the currently-active
        version for this detection. Used by the manifest sync to re-attach
        SPL/KQL/EQL when a previous seed failed to resolve the file paths."""
        sql = """
            UPDATE detection_versions
               SET yaml_content = $3,
                   compiled_spl = $4,
                   compiled_kql = $5,
                   compiled_eql = $6,
                   notes = COALESCE($7, notes)
             WHERE detection_id = $1 AND tenant_id = $2 AND status = 'active'
        """
        async with self.pool.acquire() as conn:
            await conn.execute(
                sql, detection_id, tenant_id, yaml_content,
                compiled_spl, compiled_kql, compiled_eql, notes,
            )

    async def list_versions_for(
        self,
        detection_id: str,
        tenant_id: UUID,
        platform_tenant_id: Optional[UUID] = None,
    ) -> list[dict[str, Any]]:
        params: list[Any] = [detection_id, tenant_id]
        if platform_tenant_id is not None and platform_tenant_id != tenant_id:
            params.append(platform_tenant_id)
            tenant_filter = "tenant_id IN ($2, $3)"
        else:
            tenant_filter = "tenant_id = $2"
        sql = f"""
            SELECT *
              FROM detection_versions
             WHERE detection_id = $1 AND {tenant_filter}
             ORDER BY deployed_at DESC
        """
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(sql, *params)
        return [dict(r) for r in rows]

    async def rollback_to_previous(
        self, detection_id: str, tenant_id: UUID
    ) -> Optional[dict[str, Any]]:
        """Mark current active as rolled_back, reactivate the most recent
        prior version. Returns the now-active row or None if no prior version
        exists.
        """
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                current = await conn.fetchrow(
                    """
                    SELECT version_id, deployed_at FROM detection_versions
                     WHERE detection_id = $1 AND tenant_id = $2 AND status = 'active'
                     ORDER BY deployed_at DESC
                     LIMIT 1
                    """,
                    detection_id,
                    tenant_id,
                )
                if current is None:
                    return None

                prev = await conn.fetchrow(
                    """
                    SELECT * FROM detection_versions
                     WHERE detection_id = $1
                       AND tenant_id = $2
                       AND deployed_at < $3
                     ORDER BY deployed_at DESC
                     LIMIT 1
                    """,
                    detection_id,
                    tenant_id,
                    current["deployed_at"],
                )
                if prev is None:
                    return None

                await conn.execute(
                    "UPDATE detection_versions SET status = 'rolled_back' WHERE version_id = $1",
                    current["version_id"],
                )
                await conn.execute(
                    "UPDATE detection_versions SET status = 'active' WHERE version_id = $1",
                    prev["version_id"],
                )
                row = await conn.fetchrow(
                    "SELECT * FROM detection_versions WHERE version_id = $1",
                    prev["version_id"],
                )
        return dict(row) if row else None

    # ── detection_signals ─────────────────────────────────────────────────

    async def record_signal(
        self,
        *,
        detection_id: str,
        tenant_id: UUID,
        fired_at: datetime,
        attack_id: Optional[UUID] = None,
        phase_contributed: Optional[str] = None,
        status_contributed: Optional[str] = None,
        confidence_contribution: Optional[float] = None,
    ) -> UUID:
        sql = """
            INSERT INTO detection_signals (
                detection_id, tenant_id, fired_at,
                attack_id, phase_contributed, status_contributed,
                confidence_contribution
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING signal_id
        """
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                sql,
                detection_id,
                tenant_id,
                fired_at,
                attack_id,
                phase_contributed,
                status_contributed,
                confidence_contribution,
            )
        return row["signal_id"]

    async def mark_signal_false_positive(
        self,
        signal_id: UUID,
        tenant_id: UUID,
        closed_as: str = "false_positive",
    ) -> Optional[dict[str, Any]]:
        sql = """
            UPDATE detection_signals
               SET was_false_positive = TRUE,
                   closed_as = $3
             WHERE signal_id = $1 AND tenant_id = $2
             RETURNING *
        """
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(sql, signal_id, tenant_id, closed_as)
        return dict(row) if row else None

    async def list_signals_for(
        self,
        detection_id: str,
        tenant_id: UUID,
        since: Optional[datetime] = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        if since is None:
            since = datetime.now(timezone.utc) - timedelta(days=30)
        sql = """
            SELECT *
              FROM detection_signals
             WHERE detection_id = $1 AND tenant_id = $2 AND fired_at >= $3
             ORDER BY fired_at DESC
             LIMIT $4
        """
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(sql, detection_id, tenant_id, since, limit)
        return [dict(r) for r in rows]

    # ── detection_performance ─────────────────────────────────────────────

    async def aggregate_window(
        self,
        detection_id: str,
        tenant_id: UUID,
        period_start: datetime,
        period_end: datetime,
    ) -> dict[str, Any]:
        """Compute aggregates for a single detection over a window.

        Pure read — does not write. Caller is responsible for persisting the
        result via upsert_performance().
        """
        sql = """
            SELECT
                COUNT(*)                                       AS total_fires,
                COUNT(*) FILTER (WHERE was_false_positive)     AS false_positives,
                COUNT(*) FILTER (WHERE NOT was_false_positive) AS true_positives,
                COUNT(*) FILTER (WHERE attack_id IS NOT NULL)  AS escalations,
                AVG(confidence_contribution)                   AS avg_confidence
              FROM detection_signals
             WHERE detection_id = $1
               AND tenant_id    = $2
               AND fired_at    >= $3
               AND fired_at    <  $4
        """
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(sql, detection_id, tenant_id, period_start, period_end)
        return dict(row) if row else {
            "total_fires": 0,
            "false_positives": 0,
            "true_positives": 0,
            "escalations": 0,
            "avg_confidence": None,
        }

    async def upsert_performance(
        self,
        *,
        detection_id: str,
        tenant_id: UUID,
        period_start: datetime,
        period_end: datetime,
        total_fires: int,
        false_positives: int,
        true_positives: int,
        escalations: int,
        fp_rate: Optional[float],
        avg_confidence: Optional[float],
    ) -> None:
        sql = """
            INSERT INTO detection_performance (
                detection_id, tenant_id, period_start, period_end,
                total_fires, false_positives, true_positives, escalations,
                fp_rate, avg_confidence
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        """
        async with self.pool.acquire() as conn:
            await conn.execute(
                sql,
                detection_id,
                tenant_id,
                period_start,
                period_end,
                total_fires,
                false_positives,
                true_positives,
                escalations,
                fp_rate,
                avg_confidence,
            )

    async def latest_performance(
        self, detection_id: str, tenant_id: UUID
    ) -> Optional[dict[str, Any]]:
        sql = """
            SELECT *
              FROM detection_performance
             WHERE detection_id = $1 AND tenant_id = $2
             ORDER BY computed_at DESC
             LIMIT 1
        """
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(sql, detection_id, tenant_id)
        return dict(row) if row else None

    async def daily_fires_trend(
        self,
        detection_id: str,
        tenant_id: UUID,
        days: int = 30,
    ) -> list[dict[str, Any]]:
        """Per-day fire counts over the trailing window. Used by the FE chart."""
        sql = """
            SELECT
                date_trunc('day', fired_at) AS day,
                COUNT(*) AS fires,
                COUNT(*) FILTER (WHERE was_false_positive) AS false_positives
              FROM detection_signals
             WHERE detection_id = $1
               AND tenant_id = $2
               AND fired_at >= now() - ($3 || ' days')::interval
             GROUP BY 1
             ORDER BY 1 ASC
        """
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(sql, detection_id, tenant_id, str(days))
        return [
            {
                "day": r["day"].isoformat(),
                "fires": r["fires"],
                "false_positives": r["false_positives"],
            }
            for r in rows
        ]
