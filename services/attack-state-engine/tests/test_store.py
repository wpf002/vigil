"""
Tests for AttackStateStore.

These exercise the SQL builder logic and the (de)serialization round-trip
without requiring a live PostgreSQL. The asyncpg pool/connection are mocked.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from attack_state_engine.models.attack_state import (
    AttackState,
    AttackStateStatus,
    AttackStateTransition,
    EvidenceItem,
    ImpactLevel,
    MITRETactic,
    Momentum,
    PhaseStatus,
)
from attack_state_engine.store import AttackStateStore, _deserialize_state, _serialize_state

TENANT_ID = "test-tenant"


def _state(name: str = "Test", phase: MITRETactic = MITRETactic.CREDENTIAL_ACCESS) -> AttackState:
    return AttackState(
        tenant_id=TENANT_ID,
        name=name,
        current_phase=phase,
        confidence=0.42,
        impact=ImpactLevel.HIGH,
        momentum=Momentum.STABLE,
        users=["jsmith"],
        hosts=["WORKSTATION01"],
    )


def _evidence(phase: MITRETactic = MITRETactic.CREDENTIAL_ACCESS) -> EvidenceItem:
    return EvidenceItem(
        signal_id="sig-1",
        detection_id="D1-LSASS-MEMORY-ACCESS",
        rule_name="LSASS Memory Access",
        source_siem="splunk_es",
        entity_type="host",
        entity_value="WORKSTATION01",
        raw_reference="splunk:notable:1234",
        timestamp=datetime.now(timezone.utc),
        phase=phase,
        technique_id="T1003.001",
        status_contributed=PhaseStatus.OBSERVED,
        confidence_contribution=0.25,
    )


@pytest.fixture
def mock_pool():
    """Mock asyncpg pool. acquire() returns a context manager yielding a mock connection."""
    conn = MagicMock()
    conn.execute = AsyncMock(return_value="INSERT 0 1")
    conn.fetchrow = AsyncMock(return_value=None)
    conn.fetch = AsyncMock(return_value=[])

    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=conn)
    cm.__aexit__ = AsyncMock(return_value=False)

    pool = MagicMock()
    pool.acquire = MagicMock(return_value=cm)
    pool._conn = conn
    return pool


@pytest.fixture
def store(mock_pool):
    return AttackStateStore(pool=mock_pool)


class TestSerialization:
    def test_roundtrip_preserves_all_fields(self):
        s = _state()
        s.evidence.append(_evidence())
        payload = _serialize_state(s)
        rehydrated = _deserialize_state(payload)
        assert rehydrated.attack_id == s.attack_id
        assert rehydrated.tenant_id == s.tenant_id
        assert rehydrated.current_phase == s.current_phase
        assert rehydrated.confidence == s.confidence
        assert len(rehydrated.evidence) == 1
        assert rehydrated.evidence[0].signal_id == "sig-1"

    def test_deserialize_from_dict(self):
        s = _state()
        as_dict = s.model_dump(mode="json")
        rehydrated = _deserialize_state(as_dict)
        assert rehydrated.attack_id == s.attack_id


class TestCreate:
    @pytest.mark.asyncio
    async def test_create_executes_insert(self, store, mock_pool):
        s = _state()
        await store.create(s)
        mock_pool._conn.execute.assert_awaited_once()
        sql_text = mock_pool._conn.execute.await_args.args[0]
        assert "INSERT INTO attack_states" in sql_text

    @pytest.mark.asyncio
    async def test_create_passes_correct_columns(self, store, mock_pool):
        s = _state()
        await store.create(s)
        args = mock_pool._conn.execute.await_args.args
        # args[1..] are the parameter values
        assert args[1] == s.attack_id
        assert args[2] == TENANT_ID
        assert args[4] == AttackStateStatus.ACTIVE.value
        assert args[5] == MITRETactic.CREDENTIAL_ACCESS.value
        assert args[7] == Momentum.STABLE.value
        assert args[8] == ImpactLevel.HIGH.value


class TestUpdate:
    @pytest.mark.asyncio
    async def test_update_executes_update(self, store, mock_pool):
        mock_pool._conn.execute.return_value = "UPDATE 1"
        s = _state()
        await store.update(s)
        sql_text = mock_pool._conn.execute.await_args.args[0]
        assert "UPDATE attack_states SET" in sql_text

    @pytest.mark.asyncio
    async def test_update_raises_when_missing(self, store, mock_pool):
        mock_pool._conn.execute.return_value = "UPDATE 0"
        s = _state()
        with pytest.raises(ValueError, match="not found"):
            await store.update(s)


class TestReads:
    @pytest.mark.asyncio
    async def test_get_by_id_returns_none_when_missing(self, store, mock_pool):
        mock_pool._conn.fetchrow.return_value = None
        result = await store.get_by_id(uuid4(), TENANT_ID)
        assert result is None

    @pytest.mark.asyncio
    async def test_get_by_id_deserializes_row(self, store, mock_pool):
        s = _state()
        mock_pool._conn.fetchrow.return_value = {"state": s.model_dump(mode="json")}
        out = await store.get_by_id(s.attack_id, TENANT_ID)
        assert out is not None
        assert out.attack_id == s.attack_id

    @pytest.mark.asyncio
    async def test_get_active_by_tenant_filters_by_status(self, store, mock_pool):
        await store.get_active_by_tenant(TENANT_ID, limit=10, offset=0)
        args = mock_pool._conn.fetch.await_args.args
        assert args[1] == TENANT_ID
        assert args[2] == AttackStateStatus.ACTIVE.value
        assert args[3] == 10
        assert args[4] == 0

    @pytest.mark.asyncio
    async def test_get_by_entity_uses_correct_jsonb_key(self, store, mock_pool):
        await store.get_by_entity("host", "WORKSTATION01", TENANT_ID)
        sql_text = mock_pool._conn.fetch.await_args.args[0]
        assert "state -> 'hosts'" in sql_text

        await store.get_by_entity("user", "jsmith", TENANT_ID)
        sql_text = mock_pool._conn.fetch.await_args.args[0]
        assert "state -> 'users'" in sql_text

    @pytest.mark.asyncio
    async def test_get_by_entity_unknown_type_returns_empty(self, store):
        result = await store.get_by_entity("garbage", "x", TENANT_ID)
        assert result == []


class TestSearch:
    @pytest.mark.asyncio
    async def test_search_no_filters_uses_tenant_and_status(self, store, mock_pool):
        await store.search(TENANT_ID)
        args = mock_pool._conn.fetch.await_args.args
        assert args[1] == TENANT_ID
        assert args[2] == AttackStateStatus.ACTIVE.value

    @pytest.mark.asyncio
    async def test_search_applies_phase_filter(self, store, mock_pool):
        await store.search(TENANT_ID, phase=MITRETactic.LATERAL_MOVEMENT)
        sql_text = mock_pool._conn.fetch.await_args.args[0]
        assert "current_phase" in sql_text

    @pytest.mark.asyncio
    async def test_search_applies_min_confidence(self, store, mock_pool):
        await store.search(TENANT_ID, min_confidence=0.7)
        sql_text = mock_pool._conn.fetch.await_args.args[0]
        assert "confidence >=" in sql_text


class TestTransitionLog:
    @pytest.mark.asyncio
    async def test_record_transition_inserts(self, store, mock_pool):
        t = AttackStateTransition(
            attack_id=uuid4(),
            tenant_id=TENANT_ID,
            previous_phase=MITRETactic.CREDENTIAL_ACCESS,
            new_phase=MITRETactic.LATERAL_MOVEMENT,
            previous_confidence=0.6,
            new_confidence=0.75,
            previous_momentum=Momentum.STABLE,
            new_momentum=Momentum.INCREASING,
            trigger_signal_id="sig-99",
            trigger_detection_id="D4-LATERAL-MOVEMENT-COMPROMISED-CREDS",
            is_escalation=True,
        )
        await store.record_transition(t)
        sql_text = mock_pool._conn.execute.await_args.args[0]
        assert "INSERT INTO attack_state_transitions" in sql_text
