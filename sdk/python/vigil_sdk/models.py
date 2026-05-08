"""Plain dataclass mirrors of VIGIL API responses.

Stays dataclass-only to keep the SDK Pydantic-free.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class AttackState:
    attack_id: str
    tenant_id: str
    name: str
    status: str
    current_phase: str
    confidence: float
    momentum: Optional[float] = None
    narrative: Optional[str] = None
    opened_at: Optional[str] = None
    resolved_at: Optional[str] = None
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "AttackState":
        return cls(
            attack_id=str(d.get("attack_id") or d.get("id") or ""),
            tenant_id=str(d.get("tenant_id") or ""),
            name=str(d.get("name") or ""),
            status=str(d.get("status") or "unknown"),
            current_phase=str(d.get("current_phase") or d.get("phase") or "unknown"),
            confidence=float(d.get("confidence") or 0.0),
            momentum=d.get("momentum"),
            narrative=d.get("narrative"),
            opened_at=d.get("opened_at") or d.get("created_at"),
            resolved_at=d.get("resolved_at") or d.get("closed_at"),
            raw=d,
        )


@dataclass
class DetectionVersion:
    detection_id: str
    version: str
    att_ck_tactic: str
    att_ck_technique: str
    status: str
    deployed_at: Optional[str] = None
    fp_rate: Optional[float] = None
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "DetectionVersion":
        perf = d.get("performance") or {}
        return cls(
            detection_id=str(d.get("detection_id") or ""),
            version=str(d.get("version") or "0.0.0"),
            att_ck_tactic=str(d.get("att_ck_tactic") or "unknown"),
            att_ck_technique=str(d.get("att_ck_technique") or "unknown"),
            status=str(d.get("status") or "active"),
            deployed_at=d.get("deployed_at"),
            fp_rate=perf.get("fp_rate") if isinstance(perf, dict) else None,
            raw=d,
        )


@dataclass
class ExecutiveSummary:
    active_attacks: int
    attacks_resolved_7d: int
    mttr_seconds_7d: Optional[float]
    coverage_score: Optional[float]
    open_escalations: int
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ExecutiveSummary":
        return cls(
            active_attacks=int(d.get("active_attacks") or 0),
            attacks_resolved_7d=int(d.get("attacks_resolved_7d") or 0),
            mttr_seconds_7d=d.get("mttr_seconds_7d"),
            coverage_score=d.get("coverage_score"),
            open_escalations=int(d.get("open_escalations") or 0),
            raw=d,
        )


@dataclass
class PlaybookRun:
    run_id: str
    attack_id: str
    workflow_id: str
    narrative_id: str
    status: str
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "PlaybookRun":
        return cls(
            run_id=str(d.get("run_id") or ""),
            attack_id=str(d.get("attack_id") or ""),
            workflow_id=str(d.get("workflow_id") or ""),
            narrative_id=str(d.get("narrative_id") or ""),
            status=str(d.get("status") or "unknown"),
            raw=d,
        )
