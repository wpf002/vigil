"""asyncpg queries for the detection marketplace.

Owns:
  marketplace_listings   Published detections, optionally is_curated.
  marketplace_imports    One row per tenant-import. Used both for
                         deduplication (tenant cannot import same listing
                         twice) and the downloads counter.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional
from uuid import UUID

import asyncpg
import structlog

logger = structlog.get_logger(__name__)


class MarketplaceStore:
    def __init__(self, pool: asyncpg.Pool):
        self.pool = pool

    @classmethod
    async def from_pool(cls, pool: asyncpg.Pool) -> "MarketplaceStore":
        return cls(pool)

    # ── publish / withdraw ────────────────────────────────────────────────

    async def find_listing_by_detection(
        self, *, detection_id: str, publisher_tenant_id: UUID
    ) -> Optional[dict[str, Any]]:
        sql = """
            SELECT * FROM marketplace_listings
             WHERE detection_id = $1 AND publisher_tenant_id = $2
             ORDER BY published_at DESC
             LIMIT 1
        """
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(sql, detection_id, publisher_tenant_id)
        return dict(row) if row else None

    async def upsert_listing(
        self,
        *,
        detection_id: str,
        publisher_tenant_id: UUID,
        name: str,
        description: Optional[str],
        att_ck_tactic: str,
        att_ck_technique: str,
        yaml_content: str,
        version: str,
        is_curated: bool = False,
    ) -> dict[str, Any]:
        """Create or update a listing for (publisher, detection_id).

        If a row already exists for this publisher + detection_id, the YAML,
        description, and version are refreshed and status flipped back to
        'active'. Otherwise a new row is inserted.
        """
        existing = await self.find_listing_by_detection(
            detection_id=detection_id, publisher_tenant_id=publisher_tenant_id
        )
        async with self.pool.acquire() as conn:
            if existing is None:
                row = await conn.fetchrow(
                    """
                    INSERT INTO marketplace_listings (
                        detection_id, publisher_tenant_id, name, description,
                        att_ck_tactic, att_ck_technique, yaml_content,
                        version, is_curated
                    )
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                    RETURNING *
                    """,
                    detection_id,
                    publisher_tenant_id,
                    name,
                    description,
                    att_ck_tactic,
                    att_ck_technique,
                    yaml_content,
                    version,
                    is_curated,
                )
            else:
                row = await conn.fetchrow(
                    """
                    UPDATE marketplace_listings
                       SET name = $3,
                           description = $4,
                           att_ck_tactic = $5,
                           att_ck_technique = $6,
                           yaml_content = $7,
                           version = $8,
                           is_curated = $9,
                           status = 'active',
                           updated_at = now()
                     WHERE listing_id = $1 AND publisher_tenant_id = $2
                     RETURNING *
                    """,
                    existing["listing_id"],
                    publisher_tenant_id,
                    name,
                    description,
                    att_ck_tactic,
                    att_ck_technique,
                    yaml_content,
                    version,
                    is_curated,
                )
        return dict(row)

    async def withdraw_listing(
        self, *, listing_id: UUID, publisher_tenant_id: UUID
    ) -> Optional[dict[str, Any]]:
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                UPDATE marketplace_listings
                   SET status = 'withdrawn', updated_at = now()
                 WHERE listing_id = $1 AND publisher_tenant_id = $2
                 RETURNING *
                """,
                listing_id,
                publisher_tenant_id,
            )
        return dict(row) if row else None

    # ── browse ────────────────────────────────────────────────────────────

    async def list_listings(
        self,
        *,
        tactic: Optional[str] = None,
        technique: Optional[str] = None,
        is_curated: Optional[bool] = None,
        search: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        clauses = ["status = 'active'"]
        params: list[Any] = []

        def _next() -> str:
            params_count = len(params) + 1
            return f"${params_count}"

        if tactic:
            clauses.append(f"att_ck_tactic = {_next()}")
            params.append(tactic)
        if technique:
            clauses.append(f"att_ck_technique = {_next()}")
            params.append(technique)
        if is_curated is not None:
            clauses.append(f"is_curated = {_next()}")
            params.append(is_curated)
        if search:
            placeholder = _next()
            clauses.append(f"(name ILIKE {placeholder} OR description ILIKE {placeholder})")
            params.append(f"%{search}%")

        params.append(limit)
        params.append(offset)
        sql = f"""
            SELECT * FROM marketplace_listings
             WHERE {' AND '.join(clauses)}
             ORDER BY is_curated DESC, downloads DESC, published_at DESC
             LIMIT ${len(params) - 1} OFFSET ${len(params)}
        """
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(sql, *params)
        return [dict(r) for r in rows]

    async def get_listing(self, listing_id: UUID) -> Optional[dict[str, Any]]:
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM marketplace_listings WHERE listing_id = $1",
                listing_id,
            )
        return dict(row) if row else None

    # ── imports ───────────────────────────────────────────────────────────

    async def find_import(
        self, *, listing_id: UUID, importing_tenant_id: UUID
    ) -> Optional[dict[str, Any]]:
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT * FROM marketplace_imports
                 WHERE listing_id = $1 AND importing_tenant_id = $2
                """,
                listing_id,
                importing_tenant_id,
            )
        return dict(row) if row else None

    async def record_import(
        self,
        *,
        listing_id: UUID,
        importing_tenant_id: UUID,
        local_detection_id: Optional[str] = None,
    ) -> dict[str, Any]:
        """Insert (or update if duplicate) an import row, and increment the
        listing's downloads counter only on first insert."""
        existing = await self.find_import(
            listing_id=listing_id, importing_tenant_id=importing_tenant_id
        )
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                if existing is None:
                    row = await conn.fetchrow(
                        """
                        INSERT INTO marketplace_imports (
                            listing_id, importing_tenant_id, local_detection_id
                        )
                        VALUES ($1, $2, $3)
                        RETURNING *
                        """,
                        listing_id,
                        importing_tenant_id,
                        local_detection_id,
                    )
                    await conn.execute(
                        """
                        UPDATE marketplace_listings
                           SET downloads = downloads + 1, updated_at = now()
                         WHERE listing_id = $1
                        """,
                        listing_id,
                    )
                else:
                    row = await conn.fetchrow(
                        """
                        UPDATE marketplace_imports
                           SET imported_at = now(),
                               local_detection_id = COALESCE($2, local_detection_id),
                               active = TRUE
                         WHERE import_id = $1
                         RETURNING *
                        """,
                        existing["import_id"],
                        local_detection_id,
                    )
        return dict(row)

    # ── stats ─────────────────────────────────────────────────────────────

    async def stats(self) -> dict[str, Any]:
        async with self.pool.acquire() as conn:
            total = await conn.fetchval(
                "SELECT count(*) FROM marketplace_listings WHERE status = 'active'"
            )
            by_tactic = await conn.fetch(
                """
                SELECT att_ck_tactic AS tactic, sum(downloads) AS downloads
                  FROM marketplace_listings WHERE status = 'active'
                 GROUP BY att_ck_tactic ORDER BY downloads DESC
                """
            )
            top = await conn.fetch(
                """
                SELECT listing_id, detection_id, name, downloads, att_ck_tactic
                  FROM marketplace_listings WHERE status = 'active'
                 ORDER BY downloads DESC LIMIT 10
                """
            )
        return {
            "total_listings": int(total or 0),
            "downloads_by_tactic": [
                {"tactic": r["tactic"], "downloads": int(r["downloads"] or 0)}
                for r in by_tactic
            ],
            "top_imported": [
                {
                    "listing_id": str(r["listing_id"]),
                    "detection_id": r["detection_id"],
                    "name": r["name"],
                    "downloads": int(r["downloads"] or 0),
                    "att_ck_tactic": r["att_ck_tactic"],
                }
                for r in top
            ],
        }


def serialize_listing(row: dict[str, Any], include_yaml: bool = False) -> dict[str, Any]:
    """Project a marketplace_listings row into a JSON-safe dict for the API.

    By default the YAML body is omitted (browse responses can be large);
    detail endpoints can request the first ~50 lines via include_yaml=True.
    """
    yaml_preview: Optional[str] = None
    if include_yaml and row.get("yaml_content") is not None:
        lines = row["yaml_content"].splitlines()
        yaml_preview = "\n".join(lines[:50])

    pub: Optional[datetime] = row.get("published_at")
    upd: Optional[datetime] = row.get("updated_at")
    return {
        "listing_id": str(row["listing_id"]),
        "detection_id": row["detection_id"],
        "publisher_tenant_id": str(row["publisher_tenant_id"]),
        "name": row["name"],
        "description": row.get("description"),
        "att_ck_tactic": row["att_ck_tactic"],
        "att_ck_technique": row["att_ck_technique"],
        "version": row["version"],
        "is_curated": bool(row.get("is_curated")),
        "downloads": int(row.get("downloads") or 0),
        "status": row.get("status", "active"),
        "published_at": pub.isoformat() if pub else None,
        "updated_at": upd.isoformat() if upd else None,
        "yaml_preview": yaml_preview,
    }
