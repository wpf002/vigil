"""In-transit CDM detection rules.

A lightweight predicate evaluator over normalized CDM events — the seed of a
VIGIL-native detection runtime (run detections on data in transit, instead of
pushing SIEM-dialect queries out to the customer SIEM). A rule is a set of
field predicates AND-combined; a matching event is tagged with the rule's
detection_id + state_impact so it flows into the existing correlation pipeline.

This is intentionally a CDM-field evaluator, NOT a SIEM-dialect (SPL/KQL/EQL)
executor: it operates on the already-normalized CDM shape so the same rule
works regardless of source SIEM. Stateful detections (beaconing, brute force)
need a windowed evaluator and are out of scope for this single-event MVP.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional

from .models.cdm import CDMEvent

Op = str  # equals | not_equals | contains | regex | gt | gte | lt | lte | in | exists


@dataclass
class Condition:
    field: str          # dotted CDM path, e.g. "process.process_name"
    op: Op
    value: Any = None


@dataclass
class CDMRule:
    detection_id: str
    name: str
    conditions: list[Condition]          # AND-combined
    tactic: Optional[str] = None
    technique_id: Optional[str] = None
    confidence: float = 0.6
    status: str = "Observed"             # phase status contributed on match


def rule_from_conditions(
    detection_id: str,
    name: str,
    conditions: list[dict[str, Any]],
    tactic: Optional[str] = None,
    technique_id: Optional[str] = None,
    confidence: float = 0.6,
    status: str = "Observed",
) -> Optional[CDMRule]:
    """Build a CDMRule from stored condition dicts ({field, op, value}). Returns
    None when there are no usable conditions (a metadata-only detection)."""
    conds: list[Condition] = []
    for c in conditions or []:
        fld = c.get("field")
        if not fld:
            continue
        conds.append(Condition(field=fld, op=c.get("op") or "equals", value=c.get("value")))
    if not conds:
        return None
    return CDMRule(
        detection_id=detection_id,
        name=name,
        conditions=conds,
        tactic=tactic,
        technique_id=technique_id,
        confidence=confidence,
        status=status,
    )


def resolve_field(event_dict: dict[str, Any], path: str) -> Any:
    """Walk a dotted path through a model_dump(mode='json') CDM event."""
    cur: Any = event_dict
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
        if cur is None:
            return None
    return cur


def _as_float(v: Any) -> Optional[float]:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def eval_condition(actual: Any, op: Op, target: Any) -> bool:
    if op == "exists":
        return actual is not None
    if actual is None:
        return False
    if op == "equals":
        if isinstance(target, bool) or isinstance(actual, bool):
            return bool(actual) == bool(target)
        if isinstance(target, (int, float)) and not isinstance(target, bool):
            a = _as_float(actual)
            return a is not None and a == float(target)
        return str(actual).lower() == str(target).lower()
    if op == "not_equals":
        return not eval_condition(actual, "equals", target)
    if op == "contains":
        return str(target).lower() in str(actual).lower()
    if op == "regex":
        return re.search(str(target), str(actual), re.IGNORECASE) is not None
    if op in ("gt", "gte", "lt", "lte"):
        a, t = _as_float(actual), _as_float(target)
        if a is None or t is None:
            return False
        return {"gt": a > t, "gte": a >= t, "lt": a < t, "lte": a <= t}[op]
    if op == "in":
        items = target if isinstance(target, (list, tuple, set)) else [target]
        return any(eval_condition(actual, "equals", it) for it in items)
    raise ValueError(f"unknown op: {op}")


def rule_matches(event_dict: dict[str, Any], rule: CDMRule) -> bool:
    return all(
        eval_condition(resolve_field(event_dict, c.field), c.op, c.value)
        for c in rule.conditions
    )


def evaluate(event: CDMEvent, rules: list[CDMRule]) -> list[CDMRule]:
    """Return every rule whose predicates all match the event."""
    d = event.model_dump(mode="json")
    return [r for r in rules if rule_matches(d, r)]


def best_match(event: CDMEvent, rules: list[CDMRule]) -> Optional[CDMRule]:
    """Highest-confidence matching rule, or None."""
    matches = evaluate(event, rules)
    return max(matches, key=lambda r: r.confidence) if matches else None


def apply_match(event: CDMEvent, rule: CDMRule) -> CDMEvent:
    """Tag an event in-place with a matched rule's detection metadata."""
    event.detection_id = rule.detection_id
    if event.rule_name is None:
        event.rule_name = rule.name
    event.state_impact = {
        "phase": rule.tactic,
        "status": rule.status,
        "confidence_contribution": rule.confidence,
        "technique_id": rule.technique_id,
    }
    return event


# ── Starter ruleset — single-event predicates mapped to curated detections ──────
DEFAULT_RULES: list[CDMRule] = [
    CDMRule(
        detection_id="D5-POWERSHELL-ENCODED-COMMAND",
        name="Encoded PowerShell Command",
        tactic="execution", technique_id="T1059.001", confidence=0.7,
        conditions=[
            Condition("process.process_name", "contains", "powershell"),
            Condition("process.command_line", "regex", r"-enc(odedcommand)?\b|-e\s|frombase64string"),
        ],
    ),
    CDMRule(
        detection_id="D7-UAC-BYPASS-FODHELPER",
        name="UAC Bypass via fodhelper",
        tactic="privilege-escalation", technique_id="T1548.002", confidence=0.85, status="Confirmed",
        conditions=[Condition("process.process_name", "equals", "fodhelper.exe")],
    ),
    CDMRule(
        detection_id="D6-NEW-SERVICE-INSTALL",
        name="New Service Installed via sc.exe",
        tactic="persistence", technique_id="T1543.003", confidence=0.6,
        conditions=[
            Condition("process.process_name", "equals", "sc.exe"),
            Condition("process.command_line", "contains", "create"),
        ],
    ),
    CDMRule(
        detection_id="D1-LSASS-MEMORY-ACCESS",
        name="LSASS Memory Access",
        tactic="credential-access", technique_id="T1003.001", confidence=0.75, status="Confirmed",
        conditions=[Condition("process.command_line", "regex", r"lsass(\.exe|\.dmp|\b)")],
    ),
    CDMRule(
        detection_id="D8-DOMAIN-ACCOUNT-DISCOVERY",
        name="Domain Account Discovery",
        tactic="discovery", technique_id="T1087.002", confidence=0.55,
        conditions=[Condition("process.command_line", "regex", r"net1?\s+(user|group).*/domain")],
    ),
    CDMRule(
        detection_id="D4-LATERAL-MOVEMENT-COMPROMISED-CREDS",
        name="Lateral Movement via Admin Shares / PsExec",
        tactic="lateral-movement", technique_id="T1021.002", confidence=0.65,
        conditions=[Condition("process.command_line", "regex", r"psexec|\\admin\$|\\c\$")],
    ),
]
