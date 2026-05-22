"""Tests for confidence scoring engine."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from attack_state_engine.engine.confidence import ESCALATION_THRESHOLD, ConfidenceEngine
from attack_state_engine.models.attack_state import (
    AttackState,
    EvidenceItem,
    ImpactLevel,
    MITRETactic,
    Momentum,
    PhaseStatus,
)

TENANT_ID = "test-tenant"


@pytest.fixture
def engine():
    return ConfidenceEngine()


def make_state(phase: MITRETactic = MITRETactic.CREDENTIAL_ACCESS) -> AttackState:
    return AttackState(
        tenant_id=TENANT_ID,
        name="Test Attack",
        current_phase=phase,
    )


def make_evidence(
    phase: MITRETactic = MITRETactic.CREDENTIAL_ACCESS,
    status: PhaseStatus = PhaseStatus.OBSERVED,
    contribution: float = 0.25,
    minutes_ago: int = 5,
) -> EvidenceItem:
    return EvidenceItem(
        signal_id="sig-001",
        detection_id="D1-TEST",
        rule_name="Test Rule",
        source_siem="splunk_es",
        entity_type="host",
        entity_value="WORKSTATION01",
        timestamp=datetime.now(timezone.utc) - timedelta(minutes=minutes_ago),
        phase=phase,
        technique_id="T1003.001",
        status_contributed=status,
        confidence_contribution=contribution,
    )


class TestConfidenceScoring:
    def test_empty_state_zero_confidence(self, engine):
        state = make_state()
        confidence, _, _ = engine.recalculate(state)
        assert confidence == 0.0

    def test_observed_signal_adds_confidence(self, engine):
        state = make_state()
        state.evidence.append(make_evidence(status=PhaseStatus.OBSERVED, contribution=0.25))
        confidence, _, _ = engine.recalculate(state)
        assert confidence > 0.0

    def test_confirmed_weighs_more_than_observed(self, engine):
        state_obs = make_state()
        state_obs.evidence.append(make_evidence(status=PhaseStatus.OBSERVED, contribution=0.25))
        conf_obs, _, _ = engine.recalculate(state_obs)

        state_conf = make_state()
        state_conf.evidence.append(make_evidence(status=PhaseStatus.CONFIRMED, contribution=0.25))
        conf_conf, _, _ = engine.recalculate(state_conf)

        assert conf_conf > conf_obs

    def test_confidence_capped_at_1(self, engine):
        state = make_state()
        for _ in range(20):
            state.evidence.append(make_evidence(status=PhaseStatus.CONFIRMED, contribution=1.0))
        confidence, _, _ = engine.recalculate(state)
        assert confidence == 1.0

    def test_progression_bonus_multi_phase(self, engine):
        state = make_state()
        state.evidence.append(make_evidence(phase=MITRETactic.CREDENTIAL_ACCESS, status=PhaseStatus.CONFIRMED, contribution=0.25))
        conf_single, _, _ = engine.recalculate(state)

        state.evidence.append(make_evidence(phase=MITRETactic.LATERAL_MOVEMENT, status=PhaseStatus.CONFIRMED, contribution=0.25))
        conf_multi, _, _ = engine.recalculate(state)

        assert conf_multi > conf_single


class TestMomentum:
    def test_recent_signals_stable(self, engine):
        state = make_state()
        state.evidence.append(make_evidence(minutes_ago=5))
        _, momentum, _ = engine.recalculate(state)
        assert momentum == Momentum.STABLE

    def test_recent_multi_phase_increasing(self, engine):
        state = make_state()
        state.evidence.append(make_evidence(phase=MITRETactic.CREDENTIAL_ACCESS, minutes_ago=5))
        state.evidence.append(make_evidence(phase=MITRETactic.LATERAL_MOVEMENT, minutes_ago=10))
        _, momentum, _ = engine.recalculate(state)
        assert momentum == Momentum.INCREASING

    def test_old_signals_decreasing(self, engine):
        state = make_state()
        state.evidence.append(make_evidence(minutes_ago=200))
        state.last_seen = datetime.now(timezone.utc) - timedelta(minutes=200)
        _, momentum, _ = engine.recalculate(state)
        assert momentum == Momentum.DECREASING


class TestImpact:
    def test_credential_access_high_impact(self, engine):
        state = make_state(MITRETactic.CREDENTIAL_ACCESS)
        _, _, impact = engine.recalculate(state)
        assert impact == ImpactLevel.HIGH

    def test_exfiltration_critical_impact(self, engine):
        state = make_state(MITRETactic.EXFILTRATION)
        _, _, impact = engine.recalculate(state)
        assert impact == ImpactLevel.CRITICAL

    def test_reconnaissance_low_impact(self, engine):
        state = make_state(MITRETactic.RECONNAISSANCE)
        _, _, impact = engine.recalculate(state)
        assert impact == ImpactLevel.LOW


class TestEscalation:
    def test_escalation_threshold_detection(self, engine):
        assert engine.crossed_escalation_threshold(0.65, 0.72) is True
        assert engine.crossed_escalation_threshold(0.72, 0.80) is False
        assert engine.crossed_escalation_threshold(0.50, 0.65) is False

    def test_phase_progression_detection(self, engine):
        assert engine.is_phase_progression(MITRETactic.CREDENTIAL_ACCESS, MITRETactic.LATERAL_MOVEMENT) is True
        assert engine.is_phase_progression(MITRETactic.LATERAL_MOVEMENT, MITRETactic.CREDENTIAL_ACCESS) is False
