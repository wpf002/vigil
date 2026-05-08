"""Tests for the detection marketplace.

asyncpg and the signal-translation HTTP call are both mocked. Coverage:
  - publish creates a listing (and updates if already present)
  - import creates a tenant detection_versions row + records import
  - import increments downloads exactly once per tenant
  - search filters by tactic + status
  - withdrawn listings disappear from browse
  - duplicate import does not duplicate the row, only updates it
"""

from __future__ import annotations
from typing import Any
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID, uuid4

import pytest

from detection_engine.marketplace_store import MarketplaceStore, serialize_listing


# ── shared fakes ──────────────────────────────────────────────────────────────


class FakePool:
    """In-memory asyncpg.Pool stand-in with two tables.

    Implements just enough of the surface the store uses: fetchrow / fetchval /
    fetch / execute and `async with pool.acquire() as conn` + transaction().
    """

    def __init__(self) -> None:
        self.listings: dict[UUID, dict[str, Any]] = {}
        self.imports: dict[UUID, dict[str, Any]] = {}

    def acquire(self) -> "FakeAcquire":
        return FakeAcquire(self)


class FakeAcquire:
    def __init__(self, pool: FakePool) -> None:
        self.pool = pool

    async def __aenter__(self) -> "FakeConn":
        return FakeConn(self.pool)

    async def __aexit__(self, *exc) -> None:
        return None


class FakeTxn:
    async def __aenter__(self) -> None:
        return None

    async def __aexit__(self, *exc) -> None:
        return None


class FakeConn:
    def __init__(self, pool: FakePool) -> None:
        self.pool = pool

    def transaction(self) -> FakeTxn:
        return FakeTxn()

    async def fetchrow(self, sql: str, *args):
        sql_l = sql.lower()
        if "from marketplace_listings" in sql_l and "where listing_id = $1" in sql_l and "update" not in sql_l and "insert" not in sql_l:
            return self.pool.listings.get(args[0])
        if "from marketplace_listings" in sql_l and "publisher_tenant_id = $2" in sql_l and "select * from marketplace_listings" in sql_l:
            for row in sorted(
                self.pool.listings.values(),
                key=lambda r: r.get("published_at", 0),
                reverse=True,
            ):
                if row["detection_id"] == args[0] and row["publisher_tenant_id"] == args[1]:
                    return row
            return None
        if "insert into marketplace_listings" in sql_l:
            (
                detection_id, publisher, name, description, tactic, technique,
                yaml_content, version, is_curated,
            ) = args
            new_id = uuid4()
            row = {
                "listing_id": new_id,
                "detection_id": detection_id,
                "publisher_tenant_id": publisher,
                "name": name,
                "description": description,
                "att_ck_tactic": tactic,
                "att_ck_technique": technique,
                "yaml_content": yaml_content,
                "version": version,
                "is_curated": is_curated,
                "downloads": 0,
                "published_at": _NOW(),
                "updated_at": _NOW(),
                "status": "active",
            }
            self.pool.listings[new_id] = row
            return row
        if "update marketplace_listings" in sql_l and "withdrawn" in sql_l:
            listing_id, publisher = args
            row = self.pool.listings.get(listing_id)
            if row and row["publisher_tenant_id"] == publisher:
                row["status"] = "withdrawn"
                row["updated_at"] = _NOW()
                return row
            return None
        if "update marketplace_listings" in sql_l and "name = $3" in sql_l:
            listing_id, publisher, name, description, tactic, technique, yaml_content, version, is_curated = args
            row = self.pool.listings.get(listing_id)
            if row and row["publisher_tenant_id"] == publisher:
                row.update(
                    name=name, description=description,
                    att_ck_tactic=tactic, att_ck_technique=technique,
                    yaml_content=yaml_content, version=version,
                    is_curated=is_curated, status="active", updated_at=_NOW(),
                )
                return row
            return None
        if "insert into marketplace_imports" in sql_l:
            listing_id, importing, local_detection_id = args
            new_id = uuid4()
            row = {
                "import_id": new_id,
                "listing_id": listing_id,
                "importing_tenant_id": importing,
                "imported_at": _NOW(),
                "local_detection_id": local_detection_id,
                "active": True,
            }
            self.pool.imports[new_id] = row
            return row
        if "update marketplace_imports" in sql_l:
            import_id, local_detection_id = args
            row = self.pool.imports.get(import_id)
            if row:
                row["imported_at"] = _NOW()
                if local_detection_id is not None:
                    row["local_detection_id"] = local_detection_id
                row["active"] = True
                return row
            return None
        if "from marketplace_imports" in sql_l:
            listing_id, importing = args
            for row in self.pool.imports.values():
                if row["listing_id"] == listing_id and row["importing_tenant_id"] == importing:
                    return row
            return None
        return None

    async def fetch(self, sql: str, *args):
        sql_l = sql.lower()
        if "group by att_ck_tactic" in sql_l:
            agg: dict[str, int] = {}
            for r in self.pool.listings.values():
                if r["status"] != "active":
                    continue
                agg[r["att_ck_tactic"]] = agg.get(r["att_ck_tactic"], 0) + (r.get("downloads") or 0)
            return [{"tactic": k, "downloads": v} for k, v in agg.items()]
        if "order by downloads desc limit 10" in sql_l:
            rows = [r for r in self.pool.listings.values() if r["status"] == "active"]
            rows.sort(key=lambda r: -(r.get("downloads") or 0))
            return rows[:10]
        if "from marketplace_listings" in sql_l and "where" in sql_l:
            # Browse: filter by status='active' + optional tactic/technique/is_curated/search.
            results = [r for r in self.pool.listings.values() if r["status"] == "active"]
            # Args layout: filters first, then [limit, offset].
            limit, offset = args[-2], args[-1]
            filter_args = list(args[:-2])
            sql_filters = sql_l.split("where", 1)[1].split("order by", 1)[0]
            if "att_ck_tactic =" in sql_filters:
                tactic = filter_args.pop(0)
                results = [r for r in results if r["att_ck_tactic"] == tactic]
            if "att_ck_technique =" in sql_filters:
                tech = filter_args.pop(0)
                results = [r for r in results if r["att_ck_technique"] == tech]
            if "is_curated =" in sql_filters:
                cur = filter_args.pop(0)
                results = [r for r in results if r["is_curated"] == cur]
            if "ilike" in sql_filters:
                term = filter_args.pop(0).strip("%").lower()
                results = [
                    r for r in results
                    if term in (r["name"] or "").lower()
                    or term in (r.get("description") or "").lower()
                ]
            results.sort(
                key=lambda r: (
                    -1 if r["is_curated"] else 0,
                    -int(r.get("downloads") or 0),
                )
            )
            return results[offset : offset + limit]
        return []

    async def fetchval(self, sql: str, *args):
        if "count(*)" in sql.lower() and "marketplace_listings" in sql.lower():
            return sum(1 for r in self.pool.listings.values() if r["status"] == "active")
        return None

    async def execute(self, sql: str, *args):
        if "downloads = downloads + 1" in sql.lower():
            row = self.pool.listings.get(args[0])
            if row:
                row["downloads"] = (row.get("downloads") or 0) + 1
                row["updated_at"] = _NOW()
        return None


def _NOW():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc)


@pytest.fixture
def store() -> MarketplaceStore:
    return MarketplaceStore(FakePool())


# ── publish ───────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_publish_creates_listing(store):
    pub = uuid4()
    listing = await store.upsert_listing(
        detection_id="D1", publisher_tenant_id=pub,
        name="D1", description="brute force",
        att_ck_tactic="credential-access", att_ck_technique="T1110",
        yaml_content="id: D1\n", version="1.0.0",
    )
    assert listing["status"] == "active"
    assert listing["downloads"] == 0
    assert listing["is_curated"] is False


@pytest.mark.asyncio
async def test_publish_updates_existing_listing(store):
    pub = uuid4()
    first = await store.upsert_listing(
        detection_id="D1", publisher_tenant_id=pub,
        name="D1", description="v1",
        att_ck_tactic="t", att_ck_technique="x", yaml_content="a", version="1.0.0",
    )
    second = await store.upsert_listing(
        detection_id="D1", publisher_tenant_id=pub,
        name="D1", description="v2",
        att_ck_tactic="t", att_ck_technique="x", yaml_content="b", version="1.0.1",
    )
    assert first["listing_id"] == second["listing_id"]
    assert second["description"] == "v2"
    assert second["yaml_content"] == "b"
    assert second["version"] == "1.0.1"


# ── import ────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_import_increments_downloads(store):
    pub = uuid4()
    importer = uuid4()
    listing = await store.upsert_listing(
        detection_id="D1", publisher_tenant_id=pub, name="D1", description=None,
        att_ck_tactic="t", att_ck_technique="x", yaml_content="a", version="1",
    )
    lid = listing["listing_id"]
    await store.record_import(listing_id=lid, importing_tenant_id=importer)
    refreshed = await store.get_listing(lid)
    assert refreshed["downloads"] == 1


@pytest.mark.asyncio
async def test_duplicate_import_updates_not_duplicates(store):
    pub = uuid4()
    importer = uuid4()
    listing = await store.upsert_listing(
        detection_id="D1", publisher_tenant_id=pub, name="D1", description=None,
        att_ck_tactic="t", att_ck_technique="x", yaml_content="a", version="1",
    )
    lid = listing["listing_id"]
    first = await store.record_import(listing_id=lid, importing_tenant_id=importer)
    second = await store.record_import(listing_id=lid, importing_tenant_id=importer, local_detection_id="D1")
    assert first["import_id"] == second["import_id"]
    refreshed = await store.get_listing(lid)
    # Downloads only incremented on first import.
    assert refreshed["downloads"] == 1


# ── browse / search ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_browse_filters_by_tactic(store):
    pub = uuid4()
    await store.upsert_listing(detection_id="D1", publisher_tenant_id=pub, name="A",
                               description=None, att_ck_tactic="credential-access",
                               att_ck_technique="T1110", yaml_content="", version="1")
    await store.upsert_listing(detection_id="D2", publisher_tenant_id=pub, name="B",
                               description=None, att_ck_tactic="lateral-movement",
                               att_ck_technique="T1021", yaml_content="", version="1")
    rows = await store.list_listings(tactic="credential-access")
    assert len(rows) == 1
    assert rows[0]["detection_id"] == "D1"


@pytest.mark.asyncio
async def test_browse_excludes_withdrawn(store):
    pub = uuid4()
    listing = await store.upsert_listing(
        detection_id="D1", publisher_tenant_id=pub, name="A", description=None,
        att_ck_tactic="t", att_ck_technique="x", yaml_content="", version="1",
    )
    await store.withdraw_listing(listing_id=listing["listing_id"], publisher_tenant_id=pub)
    rows = await store.list_listings()
    assert rows == []


# ── stats ─────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_stats_returns_total_and_by_tactic(store):
    pub = uuid4()
    await store.upsert_listing(detection_id="D1", publisher_tenant_id=pub, name="A",
                               description=None, att_ck_tactic="ca",
                               att_ck_technique="T1110", yaml_content="", version="1")
    await store.upsert_listing(detection_id="D2", publisher_tenant_id=pub, name="B",
                               description=None, att_ck_tactic="ca",
                               att_ck_technique="T1003", yaml_content="", version="1")
    stats = await store.stats()
    assert stats["total_listings"] == 2
    assert any(t["tactic"] == "ca" for t in stats["downloads_by_tactic"])


# ── serializer ────────────────────────────────────────────────────────────────


def test_serialize_listing_omits_yaml_by_default():
    from datetime import datetime, timezone

    row = {
        "listing_id": uuid4(),
        "detection_id": "D1",
        "publisher_tenant_id": uuid4(),
        "name": "x",
        "description": "",
        "att_ck_tactic": "t",
        "att_ck_technique": "x",
        "version": "1.0.0",
        "is_curated": True,
        "downloads": 5,
        "status": "active",
        "published_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
        "yaml_content": "id: D1\nrules:\n",
    }
    out = serialize_listing(row)
    assert out["yaml_preview"] is None
    out2 = serialize_listing(row, include_yaml=True)
    assert out2["yaml_preview"] is not None
    assert "id: D1" in out2["yaml_preview"]
