"""YAML detection validation.

Lightweight schema check — runs before compilation so the compiler can
trust the shape of its input. Errors collected and returned together so
authors don't have to fix them one at a time.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any

# Source of truth for valid MITRETactic values. Mirrors the enum in
# services/attack-state-engine/models/attack_state.py — duplicated here to
# avoid a cross-service import in this leaf service.
VALID_TACTICS = {
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
}

VALID_PHASE_STATUS = {"Observed", "Confirmed", "Blocked"}


@dataclass
class ValidationResult:
    detection_id: str
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


class ValidationError(Exception):
    def __init__(self, results: list[ValidationResult]):
        self.results = results
        msg = "; ".join(
            f"{r.detection_id}: {' | '.join(r.errors)}" for r in results if not r.ok
        )
        super().__init__(msg)


def validate(detection: dict[str, Any]) -> ValidationResult:
    """Validate a parsed YAML detection. Returns ValidationResult; never raises."""
    detection_id = str(detection.get("detection_id") or "<unknown>")
    result = ValidationResult(detection_id=detection_id)

    # Required top-level fields.
    for field_name in ("detection_id", "name"):
        if not detection.get(field_name):
            result.errors.append(f"Missing required field: {field_name}")

    # ATT&CK mapping.
    attack = detection.get("att&ck") or detection.get("attack") or {}
    if not isinstance(attack, dict):
        result.errors.append("att&ck must be a mapping")
        attack = {}
    if not attack.get("tactic"):
        result.errors.append("Missing att&ck.tactic")
    if not attack.get("technique_id"):
        result.errors.append("Missing att&ck.technique_id")

    # state_impact.
    state_impact = detection.get("state_impact")
    if not isinstance(state_impact, dict):
        result.errors.append("Missing or invalid state_impact")
    else:
        transitions_to = state_impact.get("transitions_to")
        if transitions_to not in VALID_TACTICS:
            result.errors.append(
                f"state_impact.transitions_to must be a valid MITRE tactic, got {transitions_to!r}"
            )

        status = state_impact.get("status")
        if status not in VALID_PHASE_STATUS:
            result.errors.append(
                f"state_impact.status must be one of {sorted(VALID_PHASE_STATUS)}, got {status!r}"
            )

        contribution = state_impact.get("confidence_contribution")
        try:
            contrib = float(contribution)
            if not 0.0 <= contrib <= 1.0:
                raise ValueError
        except (TypeError, ValueError):
            result.errors.append(
                f"state_impact.confidence_contribution must be a float in [0.0, 1.0], got {contribution!r}"
            )

    # Logic blocks. All three backends must be present.
    logic = detection.get("logic")
    if not isinstance(logic, dict):
        result.errors.append("Missing or invalid logic block")
    else:
        for backend in ("splunk_spl", "sentinel_kql", "elastic_eql"):
            q = logic.get(backend)
            if not isinstance(q, str) or not q.strip():
                result.errors.append(f"Missing logic.{backend}")

    return result


def validate_all(detections: list[dict[str, Any]]) -> list[ValidationResult]:
    return [validate(d) for d in detections]
