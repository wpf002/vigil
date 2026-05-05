"""
Detection registry — maps detection_id → state_impact metadata.

In Phase 1 this mirrors the YAML files under detections/. A future iteration
should compile YAML to a single JSON manifest at build time and load that.
For now we keep a small in-process dict; CDMEvents may also embed
state_impact directly (the ingestor is already wired to attach it).
"""

from __future__ import annotations
from typing import Optional, TypedDict

from ._compat import MITRETactic, PhaseStatus


class StateImpact(TypedDict):
    transitions_to: MITRETactic
    status: PhaseStatus
    confidence_contribution: float
    progression: bool


_REGISTRY: dict[str, StateImpact] = {
    "D1-LSASS-MEMORY-ACCESS": {
        "transitions_to": MITRETactic.CREDENTIAL_ACCESS,
        "status": PhaseStatus.OBSERVED,
        "confidence_contribution": 0.25,
        "progression": False,
    },
    "D2-LSASS-DUMP-CREATION": {
        "transitions_to": MITRETactic.CREDENTIAL_ACCESS,
        "status": PhaseStatus.CONFIRMED,
        "confidence_contribution": 0.50,
        "progression": False,
    },
    "D3-CREDENTIAL-REUSE-ANOMALY": {
        "transitions_to": MITRETactic.CREDENTIAL_ACCESS,
        "status": PhaseStatus.OBSERVED,
        "confidence_contribution": 0.20,
        "progression": False,
    },
    "D4-LATERAL-MOVEMENT-COMPROMISED-CREDS": {
        "transitions_to": MITRETactic.LATERAL_MOVEMENT,
        "status": PhaseStatus.OBSERVED,
        "confidence_contribution": 0.40,
        "progression": True,
    },
}


def lookup(detection_id: Optional[str]) -> Optional[StateImpact]:
    if not detection_id:
        return None
    return _REGISTRY.get(detection_id.upper())


def normalize_event_state_impact(state_impact_raw: Optional[dict]) -> Optional[StateImpact]:
    """
    Coerce a raw dict (from CDMEvent.state_impact, parsed from YAML) into
    a StateImpact with proper enum values. Returns None if essential fields missing.
    """
    if not state_impact_raw:
        return None
    try:
        phase = MITRETactic(state_impact_raw["transitions_to"])
        status = PhaseStatus(state_impact_raw["status"])
        contribution = float(state_impact_raw.get("confidence_contribution", 0.2))
        progression = bool(state_impact_raw.get("progression", False))
        return {
            "transitions_to": phase,
            "status": status,
            "confidence_contribution": contribution,
            "progression": progression,
        }
    except (KeyError, ValueError, TypeError):
        return None
