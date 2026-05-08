"""Tests for the detection-engine performance + rollback + coverage logic.

asyncpg is mocked — no live database. Each test exercises one slice of
behavior described in the Phase 3 spec.
"""

from __future__ import annotations
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID, uuid4

import pytest

from detection_engine.coverage import build_coverage_report, MITRE_TACTICS
from detection_engine.performance import (
    PerformanceAggregator,
    aggregate_all,
    aggregate_for_detection,
    compute_fp_rate,
)


# ── compute_fp_rate ───────────────────────────────────────────────────────────

def test_fp_rate_zero_fires_returns_none():
    """Guard against division by zero when a detection has not fired."""
    assert compute_fp_rate(0, 0) is None
    assert compute_fp_rate(5, 0) is None  # defensive — illegal state, still safe


def test_fp_rate_simple_case():
    assert compute_fp_rate(2, 10) == pytest.approx(0.2)


def test_fp_rate_all_fp():
    assert compute_fp_rate(7, 7) == pytest.approx(1.0)


def test_fp_rate_negative_total_treated_as_zero():
    assert compute_fp_rate(0, -1) is None


# ── aggregate_for_detection ───────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_aggregate_for_detection_writes_window():
    store = MagicMock()
    store.aggregate_window = AsyncMock(
        return_value={
            "total_fires": 10,
            "false_positives": 3,
            "true_positives": 7,
            "escalations": 2,
            "avg_confidence": 0.42,
        }
    )
    store.upsert_performance = AsyncMock()

    tenant = uuid4()
    now = datetime(2026, 5, 7, 12, 0, tzinfo=timezone.utc)

    rollup = await aggregate_for_detection(
        store=store,
        detection_id="D1-LSASS-MEMORY-ACCESS",
        tenant_id=tenant,
        window_days=7,
        now=now,
    )

    assert rollup["total_fires"] == 10
    assert rollup["false_positives"] == 3
    assert rollup["fp_rate"] == pytest.approx(0.3)
    assert rollup["avg_confidence"] == pytest.approx(0.42)
    assert rollup["period_end"] == now
    assert rollup["period_start"] == now - timedelta(days=7)

    store.aggregate_window.assert_awaited_once()
    store.upsert_performance.assert_awaited_once()
    args = store.upsert_performance.call_args.kwargs
    assert args["detection_id"] == "D1-LSASS-MEMORY-ACCESS"
    assert args["fp_rate"] == pytest.approx(0.3)


@pytest.mark.asyncio
async def test_aggregate_for_detection_no_fires():
    """A window with zero fires must persist with fp_rate=None."""
    store = MagicMock()
    store.aggregate_window = AsyncMock(
        return_value={
            "total_fires": 0,
            "false_positives": 0,
            "true_positives": 0,
            "escalations": 0,
            "avg_confidence": None,
        }
    )
    store.upsert_performance = AsyncMock()

    rollup = await aggregate_for_detection(
        store=store,
        detection_id="D2",
        tenant_id=uuid4(),
        window_days=30,
    )

    assert rollup["fp_rate"] is None
    assert rollup["avg_confidence"] is None
    assert rollup["total_fires"] == 0
    args = store.upsert_performance.call_args.kwargs
    assert args["fp_rate"] is None


@pytest.mark.asyncio
async def test_aggregate_all_runs_per_detection_and_window():
    """For every detection × {7d, 30d} window we expect one rollup."""
    store = MagicMock()
    store.list_active_detections = AsyncMock(
        return_value=[
            {"detection_id": "D1", "att_ck_tactic": "credential-access"},
            {"detection_id": "D2", "att_ck_tactic": "credential-access"},
        ]
    )
    store.aggregate_window = AsyncMock(
        return_value={
            "total_fires": 4,
            "false_positives": 1,
            "true_positives": 3,
            "escalations": 1,
            "avg_confidence": 0.5,
        }
    )
    store.upsert_performance = AsyncMock()

    written = await aggregate_all(store=store, tenant_id=uuid4())

    assert written == 4  # 2 detections × 2 windows
    assert store.upsert_performance.await_count == 4


@pytest.mark.asyncio
async def test_aggregate_all_skips_failures():
    """A failure on one window must not abort the rest."""
    store = MagicMock()
    store.list_active_detections = AsyncMock(
        return_value=[
            {"detection_id": "D1"},
            {"detection_id": "D2"},
        ]
    )

    calls = {"n": 0}

    async def flaky_window(*_args, **_kwargs):
        calls["n"] += 1
        if calls["n"] == 2:  # second call raises
            raise RuntimeError("db blip")
        return {
            "total_fires": 1,
            "false_positives": 0,
            "true_positives": 1,
            "escalations": 0,
            "avg_confidence": 0.1,
        }

    store.aggregate_window = AsyncMock(side_effect=flaky_window)
    store.upsert_performance = AsyncMock()

    written = await aggregate_all(store=store, tenant_id=uuid4())
    # 4 attempts, 1 failed → 3 written
    assert written == 3


# ── PerformanceAggregator background task ─────────────────────────────────────

@pytest.mark.asyncio
async def test_performance_aggregator_runs_initial_pass_then_stops():
    store = MagicMock()
    store.list_active_detections = AsyncMock(return_value=[])
    store.aggregate_window = AsyncMock()
    store.upsert_performance = AsyncMock()

    agg = PerformanceAggregator(
        store=store,
        tenant_id=uuid4(),
        interval_seconds=60,
    )
    agg.start()
    # Yield once so the task can run its initial aggregation.
    import asyncio
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    await agg.stop()

    store.list_active_detections.assert_awaited()


# ── rollback flow (store contract) ────────────────────────────────────────────

@pytest.mark.asyncio
async def test_rollback_returns_none_when_no_prior():
    """rollback_to_previous returns None and writes nothing if the detection
    only has one version."""
    from detection_engine.store import DetectionStore

    pool = MagicMock()
    conn = MagicMock()
    tx = MagicMock()
    tx.__aenter__ = AsyncMock(return_value=tx)
    tx.__aexit__ = AsyncMock(return_value=False)
    conn.transaction = MagicMock(return_value=tx)
    conn.fetchrow = AsyncMock(side_effect=[
        {"version_id": uuid4(), "deployed_at": datetime.now(timezone.utc)},
        None,  # no prior version
    ])
    conn.execute = AsyncMock()
    acquire = MagicMock()
    acquire.__aenter__ = AsyncMock(return_value=conn)
    acquire.__aexit__ = AsyncMock(return_value=False)
    pool.acquire = MagicMock(return_value=acquire)

    store = DetectionStore(pool)
    result = await store.rollback_to_previous("D1", uuid4())

    assert result is None
    # No status mutations should have been issued.
    conn.execute.assert_not_awaited()


@pytest.mark.asyncio
async def test_rollback_sets_correct_statuses():
    """Current → 'rolled_back', previous → 'active'."""
    from detection_engine.store import DetectionStore

    current_id = uuid4()
    prev_id = uuid4()
    deployed_at = datetime.now(timezone.utc)

    pool = MagicMock()
    conn = MagicMock()
    tx = MagicMock()
    tx.__aenter__ = AsyncMock(return_value=tx)
    tx.__aexit__ = AsyncMock(return_value=False)
    conn.transaction = MagicMock(return_value=tx)

    final_row = {
        "version_id": prev_id,
        "detection_id": "D1",
        "version": "1.0.0",
        "yaml_content": "x",
        "compiled_spl": None,
        "compiled_kql": None,
        "compiled_eql": None,
        "att_ck_tactic": "credential-access",
        "att_ck_technique": "T1003",
        "state_impact": "{}",
        "status": "active",
        "deployed_at": deployed_at,
        "deployed_by": None,
        "tenant_id": uuid4(),
        "notes": None,
    }
    conn.fetchrow = AsyncMock(side_effect=[
        {"version_id": current_id, "deployed_at": deployed_at + timedelta(days=1)},
        {**final_row, "status": "deprecated"},  # prior version, before reactivation
        final_row,                              # final state read
    ])
    conn.execute = AsyncMock()
    acquire = MagicMock()
    acquire.__aenter__ = AsyncMock(return_value=conn)
    acquire.__aexit__ = AsyncMock(return_value=False)
    pool.acquire = MagicMock(return_value=acquire)

    store = DetectionStore(pool)
    result = await store.rollback_to_previous("D1", uuid4())

    assert result is not None
    # Two status flips issued: current → rolled_back, prev → active.
    assert conn.execute.await_count == 2
    flips = [call.args for call in conn.execute.await_args_list]
    sql_text = " ".join(args[0] for args in flips)
    assert "rolled_back" in sql_text
    assert "active" in sql_text


# ── false-positive recompute ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_mark_false_positive_returns_updated_row():
    from detection_engine.store import DetectionStore

    pool = MagicMock()
    conn = MagicMock()
    expected_row = {
        "signal_id": uuid4(),
        "detection_id": "D1",
        "tenant_id": uuid4(),
        "fired_at": datetime.now(timezone.utc),
        "attack_id": None,
        "phase_contributed": None,
        "status_contributed": None,
        "confidence_contribution": None,
        "was_false_positive": True,
        "closed_as": "false_positive",
    }
    conn.fetchrow = AsyncMock(return_value=expected_row)
    acquire = MagicMock()
    acquire.__aenter__ = AsyncMock(return_value=conn)
    acquire.__aexit__ = AsyncMock(return_value=False)
    pool.acquire = MagicMock(return_value=acquire)

    store = DetectionStore(pool)
    result = await store.mark_signal_false_positive(uuid4(), uuid4())

    assert result is not None
    assert result["was_false_positive"] is True
    assert result["closed_as"] == "false_positive"


# ── coverage report ───────────────────────────────────────────────────────────

def test_coverage_report_basic():
    """Single detection covering one tactic gives 1/14 score."""
    detections = [
        {"detection_id": "D1", "att_ck_tactic": "credential-access"},
    ]
    report = build_coverage_report(detections)
    assert report["coverage_score"] == pytest.approx(round(1 / 14, 4))
    assert "credential-access" in report["covered_tactics"]
    assert len(report["uncovered_tactics"]) == 13
    assert report["counts_by_tactic"]["credential-access"] == 1
    assert report["counts_by_tactic"]["lateral-movement"] == 0


def test_coverage_report_unmapped_detection_kept_separate():
    detections = [
        {"detection_id": "D1", "att_ck_tactic": "credential-access"},
        {"detection_id": "Dx", "att_ck_tactic": "not-a-real-tactic"},
    ]
    report = build_coverage_report(detections)
    assert report["unmapped_detections"] == ["Dx"]
    # Unmapped does not count toward coverage_score.
    assert report["coverage_score"] == pytest.approx(round(1 / 14, 4))


def test_coverage_includes_all_14_tactics():
    report = build_coverage_report([])
    assert set(report["tactics"]) == set(MITRE_TACTICS)
    assert report["coverage_score"] == 0.0
    assert len(report["uncovered_tactics"]) == 14
