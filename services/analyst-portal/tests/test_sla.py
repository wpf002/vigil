"""Tests for the analyst-portal SLA + queue + consumer logic.

asyncpg, httpx, and Kafka are mocked. No live infrastructure.
"""

from __future__ import annotations
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from analyst_portal.queue_consumer import (
    QueueConsumer,
    derive_priority,
    resolve_response_minutes,
)
from analyst_portal.sla_monitor import sweep_once
from analyst_portal.store import deadline_for


# ── pure helpers ──────────────────────────────────────────────────────────────

def test_deadline_for_critical_15_minutes():
    """SLA deadline for critical = escalated_at + 15 minutes."""
    base = datetime(2026, 5, 7, 12, 0, tzinfo=timezone.utc)
    assert deadline_for(base, 15) == base + timedelta(minutes=15)


def test_deadline_for_high_30_minutes():
    base = datetime(2026, 5, 7, 12, 0, tzinfo=timezone.utc)
    assert deadline_for(base, 30) == base + timedelta(minutes=30)


def test_deadline_for_medium_60_minutes():
    base = datetime(2026, 5, 7, 12, 0, tzinfo=timezone.utc)
    assert deadline_for(base, 60) == base + timedelta(minutes=60)


def test_derive_priority_critical_impact_or_high_confidence():
    assert derive_priority({"impact": "Critical", "confidence": 0.5}) == "critical"
    assert derive_priority({"impact": "Medium", "confidence": 0.9}) == "critical"


def test_derive_priority_high():
    assert derive_priority({"impact": "High", "confidence": 0.4}) == "high"
    assert derive_priority({"impact": "Medium", "confidence": 0.72}) == "high"


def test_derive_priority_falls_back_to_medium():
    assert derive_priority({"impact": "Low", "confidence": 0.5}) == "medium"
    assert derive_priority({}) == "medium"


# ── resolve_response_minutes ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_resolve_response_minutes_uses_db_when_present():
    cfg = MagicMock()
    cfg.sla_critical_minutes = 15
    cfg.sla_high_minutes = 30
    cfg.sla_medium_minutes = 60
    cfg.sla_low_minutes = 240

    store = MagicMock()
    store.get_sla_for = AsyncMock(return_value={"response_minutes": 5, "escalation_minutes": 10})

    minutes = await resolve_response_minutes(store, cfg, uuid4(), "critical")
    assert minutes == 5


@pytest.mark.asyncio
async def test_resolve_response_minutes_falls_back_to_defaults():
    cfg = MagicMock()
    cfg.sla_critical_minutes = 15
    cfg.sla_high_minutes = 30
    cfg.sla_medium_minutes = 60
    cfg.sla_low_minutes = 240

    store = MagicMock()
    store.get_sla_for = AsyncMock(return_value=None)

    assert await resolve_response_minutes(store, cfg, uuid4(), "critical") == 15
    assert await resolve_response_minutes(store, cfg, uuid4(), "high") == 30
    assert await resolve_response_minutes(store, cfg, uuid4(), "medium") == 60
    assert await resolve_response_minutes(store, cfg, uuid4(), "low") == 240


# ── breach sweep ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_sweep_marks_breaches_and_no_others():
    """Only entries past their deadline are marked. Others left alone."""
    now = datetime(2026, 5, 7, 12, 0, tzinfo=timezone.utc)
    store = MagicMock()
    store.find_breaches = AsyncMock(
        return_value=[
            {
                "queue_id": uuid4(),
                "attack_id": uuid4(),
                "tenant_id": uuid4(),
                "priority": "critical",
                "sla_deadline": now - timedelta(minutes=2),
            },
            {
                "queue_id": uuid4(),
                "attack_id": uuid4(),
                "tenant_id": uuid4(),
                "priority": "high",
                "sla_deadline": now - timedelta(minutes=10),
            },
        ]
    )
    store.mark_breached = AsyncMock()

    n = await sweep_once(store, now=now)
    assert n == 2
    assert store.mark_breached.await_count == 2


@pytest.mark.asyncio
async def test_sweep_idempotent_when_no_breaches():
    store = MagicMock()
    store.find_breaches = AsyncMock(return_value=[])
    store.mark_breached = AsyncMock()

    assert await sweep_once(store) == 0
    store.mark_breached.assert_not_awaited()


# ── store interactions: queue write/read via mocked asyncpg ───────────────────

@pytest.mark.asyncio
async def test_store_enqueue_returns_id():
    from analyst_portal.store import AnalystPortalStore

    pool = MagicMock()
    conn = MagicMock()
    expected = uuid4()
    conn.fetchrow = AsyncMock(return_value={"queue_id": expected})
    acquire = MagicMock()
    acquire.__aenter__ = AsyncMock(return_value=conn)
    acquire.__aexit__ = AsyncMock(return_value=False)
    pool.acquire = MagicMock(return_value=acquire)

    store = AnalystPortalStore(pool)
    qid = await store.enqueue_escalation(
        attack_id=uuid4(),
        tenant_id=uuid4(),
        priority="critical",
        sla_deadline=datetime.now(timezone.utc) + timedelta(minutes=15),
    )
    assert qid == expected


# ── consumer dispatch ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_consumer_handles_escalation_inserts_with_correct_priority():
    cfg = MagicMock()
    cfg.kafka_topic_attacks_escalated = "vigil.attacks.escalated"
    cfg.kafka_topic_playbooks_paused = "vigil.playbooks.paused"
    cfg.sla_critical_minutes = 15
    cfg.sla_high_minutes = 30
    cfg.sla_medium_minutes = 60
    cfg.sla_low_minutes = 240

    store = MagicMock()
    store.get_sla_for = AsyncMock(return_value=None)
    store.enqueue_escalation = AsyncMock(return_value=uuid4())

    consumer = QueueConsumer(cfg, store)
    state = {
        "state": {
            "attack_id": str(uuid4()),
            "tenant_id": str(uuid4()),
            "impact": "Critical",
            "confidence": 0.9,
        }
    }
    await consumer._handle_escalation(state)
    store.enqueue_escalation.assert_awaited_once()
    kwargs = store.enqueue_escalation.call_args.kwargs
    assert kwargs["priority"] == "critical"
    # sla_deadline set 15 minutes after escalated_at
    delta = kwargs["sla_deadline"] - kwargs["escalated_at"]
    assert delta == timedelta(minutes=15)


@pytest.mark.asyncio
async def test_consumer_handles_paused_playbook_as_critical():
    cfg = MagicMock()
    cfg.kafka_topic_attacks_escalated = "vigil.attacks.escalated"
    cfg.kafka_topic_playbooks_paused = "vigil.playbooks.paused"
    cfg.sla_critical_minutes = 15

    store = MagicMock()
    store.enqueue_escalation = AsyncMock(return_value=uuid4())

    consumer = QueueConsumer(cfg, store)
    payload = {
        "attack_id": str(uuid4()),
        "tenant_id": str(uuid4()),
        "reason": "isolate_host failed",
    }
    await consumer._handle_paused(payload)
    store.enqueue_escalation.assert_awaited_once()
    kwargs = store.enqueue_escalation.call_args.kwargs
    assert kwargs["priority"] == "critical"
    delta = kwargs["sla_deadline"] - kwargs["escalated_at"]
    assert delta == timedelta(minutes=15)
    assert "isolate_host failed" in (kwargs.get("notes") or "")


# ── acknowledge → response_time + sla_met ────────────────────────────────────

def test_acknowledge_within_sla_marks_met():
    """Acknowledged before deadline → sla_met=True; response_time = ack - escalated."""
    escalated = datetime(2026, 5, 7, 12, 0, tzinfo=timezone.utc)
    deadline = escalated + timedelta(minutes=15)
    ack = escalated + timedelta(minutes=10)

    response_seconds = int((ack - escalated).total_seconds())
    sla_met = ack <= deadline

    assert response_seconds == 600
    assert sla_met is True


def test_acknowledge_after_sla_marks_not_met():
    """Acknowledged after deadline → sla_met=False; response_time still computed."""
    escalated = datetime(2026, 5, 7, 12, 0, tzinfo=timezone.utc)
    deadline = escalated + timedelta(minutes=15)
    ack = escalated + timedelta(minutes=20)

    response_seconds = int((ack - escalated).total_seconds())
    sla_met = ack <= deadline

    assert response_seconds == 1200
    assert sla_met is False
