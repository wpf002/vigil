"""
Confidence Scoring Engine

Deterministic confidence calculation — no ML.
Logic is fully explainable and auditable.

Formula:
  confidence = (confirmed_signals * 0.5) + (supporting_signals * 0.2) + (progression_bonus * 0.3)
  capped at 1.0

Momentum:
  Increasing  — new phase progression within momentum_window_minutes
  Stable      — no new progression signals
  Decreasing  — inactivity_threshold_minutes exceeded with no new signals
"""

from __future__ import annotations
from datetime import datetime, timedelta, timezone
from ..models.attack_state import AttackState, EvidenceItem, ImpactLevel, Momentum, MITRETactic, PhaseStatus


# Weight constants — adjust to tune sensitivity
CONFIRMED_SIGNAL_WEIGHT = 0.50
SUPPORTING_SIGNAL_WEIGHT = 0.20
PROGRESSION_BONUS_WEIGHT = 0.30

# Confidence thresholds
ESCALATION_THRESHOLD = 0.70       # Notify analyst
HIGH_CONFIDENCE_THRESHOLD = 0.85  # Auto-recommend immediate response

# Momentum windows
MOMENTUM_INCREASING_WINDOW_MINUTES = 30
MOMENTUM_DECREASING_THRESHOLD_MINUTES = 120

# Kill chain phase order — used to calculate progression bonus
PHASE_ORDER = [
    MITRETactic.RECONNAISSANCE,
    MITRETactic.RESOURCE_DEVELOPMENT,
    MITRETactic.INITIAL_ACCESS,
    MITRETactic.EXECUTION,
    MITRETactic.PERSISTENCE,
    MITRETactic.PRIVILEGE_ESCALATION,
    MITRETactic.DEFENSE_EVASION,
    MITRETactic.CREDENTIAL_ACCESS,
    MITRETactic.DISCOVERY,
    MITRETactic.LATERAL_MOVEMENT,
    MITRETactic.COLLECTION,
    MITRETactic.COMMAND_AND_CONTROL,
    MITRETactic.EXFILTRATION,
    MITRETactic.IMPACT,
]

# Impact escalates as the attacker progresses through the kill chain
PHASE_IMPACT_MAP = {
    MITRETactic.RECONNAISSANCE: ImpactLevel.LOW,
    MITRETactic.RESOURCE_DEVELOPMENT: ImpactLevel.LOW,
    MITRETactic.INITIAL_ACCESS: ImpactLevel.MEDIUM,
    MITRETactic.EXECUTION: ImpactLevel.MEDIUM,
    MITRETactic.PERSISTENCE: ImpactLevel.MEDIUM,
    MITRETactic.PRIVILEGE_ESCALATION: ImpactLevel.HIGH,
    MITRETactic.DEFENSE_EVASION: ImpactLevel.HIGH,
    MITRETactic.CREDENTIAL_ACCESS: ImpactLevel.HIGH,
    MITRETactic.DISCOVERY: ImpactLevel.MEDIUM,
    MITRETactic.LATERAL_MOVEMENT: ImpactLevel.HIGH,
    MITRETactic.COLLECTION: ImpactLevel.HIGH,
    MITRETactic.COMMAND_AND_CONTROL: ImpactLevel.CRITICAL,
    MITRETactic.EXFILTRATION: ImpactLevel.CRITICAL,
    MITRETactic.IMPACT: ImpactLevel.CRITICAL,
}


class ConfidenceEngine:
    """
    Stateless scorer. Call recalculate() after any state change.
    Returns updated confidence, momentum, and impact — never mutates in place.
    """

    def recalculate(self, state: AttackState) -> tuple[float, Momentum, ImpactLevel]:
        """
        Returns (confidence, momentum, impact).
        Caller is responsible for applying these to the AttackState.
        """
        confidence = self._score_confidence(state)
        momentum = self._score_momentum(state)
        impact = PHASE_IMPACT_MAP.get(state.current_phase, ImpactLevel.MEDIUM)
        return round(confidence, 4), momentum, impact

    def _score_confidence(self, state: AttackState) -> float:
        confirmed = sum(
            e.confidence_contribution
            for e in state.evidence
            if e.status_contributed == PhaseStatus.CONFIRMED
        )
        supporting = sum(
            e.confidence_contribution
            for e in state.evidence
            if e.status_contributed == PhaseStatus.OBSERVED
        )
        progression = self._progression_bonus(state)

        raw = (
            (confirmed * CONFIRMED_SIGNAL_WEIGHT) +
            (supporting * SUPPORTING_SIGNAL_WEIGHT) +
            (progression * PROGRESSION_BONUS_WEIGHT)
        )
        return min(raw, 1.0)

    def _progression_bonus(self, state: AttackState) -> float:
        """
        Bonus for multi-phase progression. Each distinct confirmed phase
        beyond the first adds to the progression score.
        Max bonus = 1.0 (achieved with 4+ distinct phases confirmed).
        """
        confirmed_phases = {
            e.phase for e in state.evidence
            if e.status_contributed == PhaseStatus.CONFIRMED
        }
        distinct_phase_count = len(confirmed_phases)
        if distinct_phase_count <= 1:
            return 0.0
        # 0.25 per additional phase, capped at 1.0
        return min((distinct_phase_count - 1) * 0.25, 1.0)

    def _score_momentum(self, state: AttackState) -> Momentum:
        now = datetime.now(timezone.utc)
        increasing_cutoff = now - timedelta(minutes=MOMENTUM_INCREASING_WINDOW_MINUTES)
        decreasing_cutoff = now - timedelta(minutes=MOMENTUM_DECREASING_THRESHOLD_MINUTES)

        # Check for recent progression (phase advance in the kill chain)
        recent_phases = {
            e.phase for e in state.evidence
            if e.timestamp >= increasing_cutoff
            and e.status_contributed in (PhaseStatus.CONFIRMED, PhaseStatus.OBSERVED)
        }

        if len(recent_phases) > 1:
            return Momentum.INCREASING

        recent_signals = [e for e in state.evidence if e.timestamp >= increasing_cutoff]
        if recent_signals:
            return Momentum.STABLE

        # No signals in the inactivity window
        if state.last_seen < decreasing_cutoff:
            return Momentum.DECREASING

        return Momentum.STABLE

    def crossed_escalation_threshold(
        self, previous_confidence: float, new_confidence: float
    ) -> bool:
        return previous_confidence < ESCALATION_THRESHOLD <= new_confidence

    def phase_index(self, phase: MITRETactic) -> int:
        try:
            return PHASE_ORDER.index(phase)
        except ValueError:
            return -1

    def is_phase_progression(
        self, previous_phase: MITRETactic, new_phase: MITRETactic
    ) -> bool:
        return self.phase_index(new_phase) > self.phase_index(previous_phase)
