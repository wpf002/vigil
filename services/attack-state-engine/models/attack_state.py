"""
AttackState Model

The core primitive of VIGIL. Represents a live attack narrative,
not an alert. Every signal updates state — nothing creates a raw alert.
"""

from __future__ import annotations
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from uuid import UUID, uuid4
from pydantic import BaseModel, Field


class MITRETactic(str, Enum):
    RECONNAISSANCE = "reconnaissance"
    RESOURCE_DEVELOPMENT = "resource-development"
    INITIAL_ACCESS = "initial-access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege-escalation"
    DEFENSE_EVASION = "defense-evasion"
    CREDENTIAL_ACCESS = "credential-access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral-movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command-and-control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


class ImpactLevel(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class Momentum(str, Enum):
    INCREASING = "Increasing"
    STABLE = "Stable"
    DECREASING = "Decreasing"


class PhaseStatus(str, Enum):
    OBSERVED = "Observed"
    CONFIRMED = "Confirmed"
    BLOCKED = "Blocked"


class AttackStateStatus(str, Enum):
    ACTIVE = "active"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


# ─── Evidence ─────────────────────────────────────────────────────────────────

class EvidenceItem(BaseModel):
    """A single piece of evidence contributing to the attack state."""
    evidence_id: UUID = Field(default_factory=uuid4)
    signal_id: str                              # CDMEvent.event_id
    detection_id: Optional[str] = None          # Links to YAML detection definition
    rule_name: Optional[str] = None
    source_siem: str
    entity_type: str                            # host | user | process | network
    entity_value: str                           # e.g. "WORKSTATION01", "jsmith"
    raw_reference: Optional[str] = None         # Brief human-readable pointer to raw event
    timestamp: datetime
    phase: MITRETactic
    technique_id: Optional[str] = None
    status_contributed: PhaseStatus
    confidence_contribution: float              # 0.0–1.0


# ─── Phase State ──────────────────────────────────────────────────────────────

class PhaseState(BaseModel):
    """State of a single ATT&CK tactic within the attack."""
    phase: MITRETactic
    status: PhaseStatus
    technique_id: Optional[str] = None
    technique_name: Optional[str] = None
    first_seen: datetime
    last_seen: datetime
    evidence_ids: list[UUID] = Field(default_factory=list)
    confidence: float = 0.0


# ─── Response ─────────────────────────────────────────────────────────────────

class ResponseAction(BaseModel):
    action_type: str       # isolate_host | kill_process | reset_credentials | block_protocol | etc.
    priority: str          # immediate | follow_up
    target_entity: str
    description: str
    automated: bool = False
    completed: bool = False
    completed_at: Optional[datetime] = None


class ResponseStatus(BaseModel):
    containment: bool = False
    eradication: bool = False
    recovery: bool = False
    containment_at: Optional[datetime] = None
    eradication_at: Optional[datetime] = None
    recovery_at: Optional[datetime] = None


# ─── Core AttackState ─────────────────────────────────────────────────────────

class AttackState(BaseModel):
    """
    Live attack narrative. Updated deterministically by the correlation engine.
    Analysts work this object — not raw alerts.
    """

    # Identity
    attack_id: UUID = Field(default_factory=uuid4)
    tenant_id: str
    name: str                          # e.g. "Credential Access → Lateral Movement: WORKSTATION04"
    description: Optional[str] = None

    # Current state
    status: AttackStateStatus = AttackStateStatus.ACTIVE
    current_phase: MITRETactic
    confidence: float = 0.0            # 0.0–1.0, deterministic formula
    impact: ImpactLevel = ImpactLevel.MEDIUM
    momentum: Momentum = Momentum.STABLE

    # Phase history
    phases: list[PhaseState] = Field(default_factory=list)

    # Entities involved
    users: list[str] = Field(default_factory=list)
    hosts: list[str] = Field(default_factory=list)
    processes: list[str] = Field(default_factory=list)
    credentials: list[str] = Field(default_factory=list)
    cloud_resources: list[str] = Field(default_factory=list)

    # Full evidence chain — never truncated
    evidence: list[EvidenceItem] = Field(default_factory=list)

    # AI-generated narrative (populated by ai-engine)
    narrative: Optional[str] = None
    predicted_next_phase: Optional[MITRETactic] = None
    analyst_summary: Optional[str] = None

    # Response
    recommended_actions: list[ResponseAction] = Field(default_factory=list)
    response_status: ResponseStatus = Field(default_factory=ResponseStatus)

    # Timestamps
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_updated: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat(), UUID: lambda v: str(v)}

    def get_phase(self, tactic: MITRETactic) -> Optional[PhaseState]:
        return next((p for p in self.phases if p.phase == tactic), None)

    def get_confirmed_signal_count(self) -> int:
        return sum(1 for e in self.evidence if e.status_contributed == PhaseStatus.CONFIRMED)

    def get_supporting_signal_count(self) -> int:
        return sum(1 for e in self.evidence if e.status_contributed == PhaseStatus.OBSERVED)


# ─── State Transition Event (published to Kafka) ──────────────────────────────

class AttackStateTransition(BaseModel):
    """Published to vigil.attacks.updated when state changes."""
    transition_id: UUID = Field(default_factory=uuid4)
    attack_id: UUID
    tenant_id: str
    previous_phase: Optional[MITRETactic]
    new_phase: MITRETactic
    previous_confidence: float
    new_confidence: float
    previous_momentum: Momentum
    new_momentum: Momentum
    trigger_signal_id: str
    trigger_detection_id: Optional[str]
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    is_escalation: bool = False        # True if confidence crossed escalation threshold

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat(), UUID: lambda v: str(v)}
