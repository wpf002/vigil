"""
Tests for SignalHandler.

The store, entity index, and publisher are mocked. The Pydantic state model,
ConfidenceEngine, and detection registry are exercised in-process. No live
Kafka, PostgreSQL, or Redis is required.
"""

from __future__ import annotations
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID, uuid4

import pytest

from correlation_engine._compat import (
    AttackState,
    AttackStateStatus,
    AttackStateTransition,
    CDMEvent,
    MITRETactic,
    PhaseStatus,
)
from correlation_engine.handlers.signal_handler import SignalHandler


TENANT = "test-tenant"


# ── helpers ──────────────────────────────────────────────────────────────────

def _event(
    detection_id: str = "D1-LSASS-MEMORY-ACCESS",
    hostname: str = "WORKSTATION01",
    username: Optional[str] = "jsmith",
    process: Optional[str] = "powershell.exe",
    rule_name: str = "LSASS Memory Access",
    timestamp: Optional[datetime] = None,
    state_impact: Optional[dict] = None,
) -> CDMEvent:
    return CDMEvent(
        tenant_id=TENANT,
        source_event_id=f"src-{uuid4().hex[:8]}",
        source_siem="splunk_es",
        timestamp=timestamp or datetime.now(timezone.utc),
        title=rule_name,
        rule_name=rule_name,
        detection_id=detection_id,
        state_impact=state_impact,
        host={"hostname": hostname, "ip": None} if hostname else None,
        user={"username": username} if username else None,
        process={"process_name": process} if process else None,
        mitre={"technique_id": "T1003.001", "technique": "OS Credential Dumping"},
    )


class FakeEntityIndex:
    """In-memory stand-in for the Redis-backed EntityIndex."""

    def __init__(self):
        self._processed: set[str] = set()
        self._bindings: dict[tuple[str, str, str], UUID] = {}

    async def mark_processed_if_new(self, tenant_id: str, event_id: str) -> bool:
        key = f"{tenant_id}:{event_id}"
        if key in self._processed:
            return False
        self._processed.add(key)
        return True

    async def unmark_processed(self, tenant_id: str, event_id: str) -> None:
        self._processed.discard(f"{tenant_id}:{event_id}")

    async def lookup_any(self, tenant_id, entities):
        for et, ev in entities:
            attack_id = self._bindings.get((tenant_id, et, ev.lower()))
            if attack_id:
                return attack_id
        return None

    async def bind(self, tenant_id, entities, attack_id):
        for et, ev in entities:
            self._bindings[(tenant_id, et, ev.lower())] = attack_id

    @asynccontextmanager
    async def lock(self, tenant_id, lock_key, **kwargs):
        yield


class FakePublisher:
    def __init__(self):
        self.created: list[AttackState] = []
        self.updated: list[tuple[AttackState, AttackStateTransition]] = []
        self.escalated: list[tuple[AttackState, AttackStateTransition]] = []

    async def publish_attack_created(self, state):
        self.created.append(state)
        return True

    async def publish_attack_updated(self, state, transition):
        self.updated.append((state, transition))
        return True

    async def publish_attack_escalated(self, state, transition):
        self.escalated.append((state, transition))
        return True


@pytest.fixture
def store():
    """Mock store backed by an in-memory dict keyed by attack_id."""
    storage: dict[UUID, AttackState] = {}

    async def create(state):
        storage[state.attack_id] = state.model_copy(deep=True)

    async def update(state):
        if state.attack_id not in storage:
            raise ValueError("not found")
        storage[state.attack_id] = state.model_copy(deep=True)

    async def get_by_id(attack_id, tenant_id):
        s = storage.get(attack_id)
        if s and s.tenant_id == tenant_id:
            return s.model_copy(deep=True)
        return None

    async def get_by_entity(entity_type, entity_value, tenant_id):
        keymap = {
            "host": "hosts",
            "user": "users",
            "process": "processes",
        }
        attr = keymap.get(entity_type)
        if not attr:
            return []
        out = []
        for s in storage.values():
            if s.tenant_id != tenant_id or s.status != AttackStateStatus.ACTIVE:
                continue
            if entity_value in getattr(s, attr):
                out.append(s.model_copy(deep=True))
        return out

    async def record_transition(transition):
        return None

    mock = MagicMock()
    mock.create = AsyncMock(side_effect=create)
    mock.update = AsyncMock(side_effect=update)
    mock.get_by_id = AsyncMock(side_effect=get_by_id)
    mock.get_by_entity = AsyncMock(side_effect=get_by_entity)
    mock.record_transition = AsyncMock(side_effect=record_transition)
    mock._storage = storage
    return mock


@pytest.fixture
def entity_index():
    return FakeEntityIndex()


@pytest.fixture
def publisher():
    return FakePublisher()


@pytest.fixture
def handler(store, entity_index, publisher):
    return SignalHandler(store=store, entity_index=entity_index, publisher=publisher)


# ── tests ────────────────────────────────────────────────────────────────────

class TestCreateNewAttack:
    @pytest.mark.asyncio
    async def test_first_signal_creates_attack(self, handler, store, publisher):
        event = _event()
        state = await handler.handle(event)

        assert state is not None
        assert state.tenant_id == TENANT
        assert state.current_phase == MITRETactic.CREDENTIAL_ACCESS
        assert "WORKSTATION01" in state.hosts
        assert "jsmith" in state.users
        assert len(state.evidence) == 1
        store.create.assert_awaited_once()
        assert len(publisher.created) == 1
        assert len(publisher.updated) == 0
        assert len(publisher.escalated) == 0

    @pytest.mark.asyncio
    async def test_signal_without_state_impact_is_skipped(self, handler, store, publisher):
        event = _event(detection_id="UNKNOWN-DETECTION")
        event.state_impact = None
        state = await handler.handle(event)
        assert state is None
        store.create.assert_not_awaited()
        assert publisher.created == []

    @pytest.mark.asyncio
    async def test_event_state_impact_used_when_no_registry(self, handler, store, publisher):
        event = _event(
            detection_id="CUSTOM-DETECTION",
            state_impact={
                "transitions_to": "execution",
                "status": "Observed",
                "confidence_contribution": 0.3,
            },
        )
        state = await handler.handle(event)
        assert state is not None
        assert state.current_phase == MITRETactic.EXECUTION


class TestIdempotency:
    @pytest.mark.asyncio
    async def test_duplicate_event_id_is_skipped(self, handler, store, publisher):
        event = _event()
        first = await handler.handle(event)
        second = await handler.handle(event)
        assert first is not None
        assert second is None
        store.create.assert_awaited_once()
        assert len(publisher.created) == 1

    @pytest.mark.asyncio
    async def test_two_distinct_events_same_entity_correlate(self, handler, store, publisher):
        e1 = _event(detection_id="D1-LSASS-MEMORY-ACCESS")
        e2 = _event(detection_id="D2-LSASS-DUMP-CREATION")
        s1 = await handler.handle(e1)
        s2 = await handler.handle(e2)
        assert s1 is not None and s2 is not None
        assert s1.attack_id == s2.attack_id
        assert len(s2.evidence) == 2
        store.create.assert_awaited_once()
        store.update.assert_awaited()


class TestExistingAttackUpdate:
    @pytest.mark.asyncio
    async def test_observed_then_confirmed_increases_confidence(self, handler, publisher):
        e1 = _event(detection_id="D1-LSASS-MEMORY-ACCESS")  # Observed
        e2 = _event(detection_id="D2-LSASS-DUMP-CREATION")  # Confirmed
        s1 = await handler.handle(e1)
        s2 = await handler.handle(e2)
        assert s2.confidence > s1.confidence
        assert any(p.status == PhaseStatus.CONFIRMED for p in s2.phases)

    @pytest.mark.asyncio
    async def test_phase_progression_advances_current_phase(self, handler, publisher):
        e1 = _event(detection_id="D2-LSASS-DUMP-CREATION", hostname="WORKSTATION01")
        e2 = _event(detection_id="D4-LATERAL-MOVEMENT-COMPROMISED-CREDS", hostname="WORKSTATION01")
        s1 = await handler.handle(e1)
        s2 = await handler.handle(e2)
        assert s1.current_phase == MITRETactic.CREDENTIAL_ACCESS
        assert s2.current_phase == MITRETactic.LATERAL_MOVEMENT
        # Transition should appear in the updated stream
        assert len(publisher.updated) == 1
        assert publisher.updated[0][1].previous_phase == MITRETactic.CREDENTIAL_ACCESS
        assert publisher.updated[0][1].new_phase == MITRETactic.LATERAL_MOVEMENT


class TestEntityCorrelation:
    @pytest.mark.asyncio
    async def test_correlates_via_redis_cache(self, handler, store):
        e1 = _event(hostname="HOST-A", username="alice")
        e2 = _event(hostname="HOST-A", username=None, process=None)
        s1 = await handler.handle(e1)
        s2 = await handler.handle(e2)
        assert s1.attack_id == s2.attack_id
        # Cache should hit; only the first DB lookup may have happened.

    @pytest.mark.asyncio
    async def test_correlates_via_db_when_cache_miss(self, handler, store, entity_index):
        e1 = _event(hostname="HOST-B", username="bob")
        s1 = await handler.handle(e1)
        # Wipe the entity-index cache so the next event must hit the DB
        entity_index._bindings.clear()
        e2 = _event(hostname="HOST-B", username=None, process=None)
        s2 = await handler.handle(e2)
        assert s1.attack_id == s2.attack_id
        store.get_by_entity.assert_awaited()

    @pytest.mark.asyncio
    async def test_distinct_entities_create_distinct_attacks(self, handler):
        e1 = _event(hostname="HOST-X", username="user-x", process=None)
        e2 = _event(hostname="HOST-Y", username="user-y", process=None)
        s1 = await handler.handle(e1)
        s2 = await handler.handle(e2)
        assert s1.attack_id != s2.attack_id


class TestEscalation:
    @pytest.mark.asyncio
    async def test_publishes_to_escalated_topic_on_threshold_cross(
        self, handler, publisher
    ):
        # Use synthetic detection IDs so the embedded state_impact is honored
        # — we want enough cumulative weight to cross the 0.70 escalation gate.
        e1 = _event(
            detection_id="SYNTH-CRED-ACCESS",
            hostname="HOST-Z",
            state_impact={
                "transitions_to": "credential-access",
                "status": "Confirmed",
                "confidence_contribution": 1.0,
            },
        )
        e2 = _event(
            detection_id="SYNTH-LATERAL",
            hostname="HOST-Z",
            state_impact={
                "transitions_to": "lateral-movement",
                "status": "Confirmed",
                "confidence_contribution": 1.0,
                "progression": True,
            },
        )
        s1 = await handler.handle(e1)
        s2 = await handler.handle(e2)
        assert s1.confidence < 0.70
        assert s2.confidence >= 0.70
        # Escalation must be published exactly once: on the cross.
        assert len(publisher.escalated) == 1
        assert publisher.escalated[0][1].is_escalation is True


class TestRetryAfterFailure:
    @pytest.mark.asyncio
    async def test_handler_failure_releases_idempotency_claim(
        self, store, entity_index, publisher
    ):
        store.create = AsyncMock(side_effect=RuntimeError("db down"))
        handler = SignalHandler(store=store, entity_index=entity_index, publisher=publisher)
        event = _event()
        with pytest.raises(RuntimeError):
            await handler.handle(event)
        # Idempotency claim should have been rolled back so a retry can re-process.
        assert await entity_index.mark_processed_if_new(TENANT, str(event.event_id)) is True
