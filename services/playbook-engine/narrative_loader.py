"""Loads attack-narrative YAML templates and resolves the playbook to run.

Each narrative has a `response_playbooks` map keyed by playbook_name. The
key encodes the trigger via convention (e.g. credential_access_confirmed),
but the authoritative trigger is the `trigger:` string. We match against
phase + status by simple substring inclusion — sufficient for the curated
narrative library we ship today.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional

import structlog
import yaml

logger = structlog.get_logger(__name__)


# Read-only context-gathering actions, safe to run automatically before any
# state-changing response. Used to classify a playbook action's `kind` when the
# YAML doesn't state it explicitly.
ENRICHMENT_ACTION_TYPES: set[str] = {
    "ioc_lookup",
    "asset_context",
    "user_context",
    "threat_intel_lookup",
    "geo_lookup",
    "reputation_check",
}


def classify_kind(action_type: str) -> str:
    return "enrichment" if action_type in ENRICHMENT_ACTION_TYPES else "response"


@dataclass
class PlaybookAction:
    action_type: str
    target: str
    automated: bool = False
    protocol: Optional[str] = None
    description: str = ""
    kind: str = "response"  # "enrichment" (read-only) | "response" (state-changing)

    def to_response_action(self, priority: str, target_entity: str) -> dict[str, Any]:
        """Shape this action into the AttackState.recommended_actions schema."""
        return {
            "action_type": self.action_type,
            "priority": priority,
            "kind": self.kind,
            "target_entity": target_entity,
            "description": self.description or self.action_type.replace("_", " ").title(),
            "automated": self.automated,
            "completed": False,
            "completed_at": None,
        }


@dataclass
class Playbook:
    narrative_id: str
    playbook_name: str
    trigger: str  # raw/display form
    # Structured trigger condition (parsed from the string or a YAML dict).
    trigger_mode: str = "auto"          # "auto" fires on the pipeline; "manual" only on demand
    trigger_phase: Optional[str] = None
    trigger_status: Optional[str] = None
    min_confidence: float = 0.0
    trigger_detection_id: Optional[str] = None
    enrichment: list[PlaybookAction] = field(default_factory=list)
    immediate: list[PlaybookAction] = field(default_factory=list)
    follow_up: list[PlaybookAction] = field(default_factory=list)


_TRIG_PHASE = re.compile(r"phase\s*[=:]\s*([a-z0-9\-_]+)", re.I)
_TRIG_STATUS = re.compile(r"status\s*[=:]\s*([a-z]+)", re.I)
_TRIG_CONF = re.compile(r"confidence\s*>=?\s*([0-9.]+)", re.I)


def _parse_trigger(value: Any) -> dict[str, Any]:
    """Parse a playbook trigger into structured fields.

    Accepts either the legacy free-text string
    (``phase=credential-access AND status=Confirmed AND confidence>=0.65``)
    or a YAML mapping (``{mode, phase, status, min_confidence, detection_id}``).
    """
    if isinstance(value, dict):
        conf = value.get("min_confidence", value.get("confidence", 0.0))
        return {
            "raw": str(value.get("raw") or value),
            "mode": str(value.get("mode") or "auto").lower(),
            "phase": value.get("phase"),
            "status": value.get("status"),
            "min_confidence": float(conf or 0.0),
            "detection_id": value.get("detection_id"),
        }
    s = str(value or "")
    m_phase, m_status, m_conf = _TRIG_PHASE.search(s), _TRIG_STATUS.search(s), _TRIG_CONF.search(s)
    return {
        "raw": s,
        "mode": "manual" if "manual" in s.lower() else "auto",
        "phase": m_phase.group(1) if m_phase else None,
        "status": m_status.group(1) if m_status else None,
        "min_confidence": float(m_conf.group(1)) if m_conf else 0.0,
        "detection_id": None,
    }


@dataclass
class Narrative:
    narrative_id: str
    name: str
    phases: list[str]
    raw: dict[str, Any]
    playbooks: list[Playbook] = field(default_factory=list)


def _load_action(node: dict[str, Any], *, force_kind: Optional[str] = None) -> PlaybookAction:
    action_type = str(node.get("action") or "unknown")
    # force_kind (the YAML block) wins, then explicit `kind`, then inference.
    kind = force_kind or str(node.get("kind") or classify_kind(action_type))
    return PlaybookAction(
        action_type=action_type,
        target=str(node.get("target") or "unknown"),
        automated=bool(node.get("automated", False)),
        protocol=node.get("protocol"),
        description=str(node.get("description") or ""),
        kind=kind,
    )


def _build_playbook(narrative_id: str, pb_name: str, pb_node: dict[str, Any]) -> Playbook:
    trig = _parse_trigger(pb_node.get("trigger"))
    return Playbook(
        narrative_id=narrative_id,
        playbook_name=pb_name,
        trigger=trig["raw"],
        trigger_mode=trig["mode"],
        trigger_phase=trig["phase"],
        trigger_status=trig["status"],
        min_confidence=trig["min_confidence"],
        trigger_detection_id=trig["detection_id"],
        enrichment=[_load_action(a, force_kind="enrichment")
                    for a in (pb_node.get("enrichment") or []) if isinstance(a, dict)],
        immediate=[_load_action(a) for a in (pb_node.get("immediate") or []) if isinstance(a, dict)],
        follow_up=[_load_action(a) for a in (pb_node.get("follow_up") or []) if isinstance(a, dict)],
    )


def playbook_from_definition(d: dict[str, Any]) -> Playbook:
    """Convert a DB playbook_definitions row into a runnable Playbook.

    Each action dict carries {action_type, target, kind, priority, automated,
    description}; we split them into enrichment / immediate / follow_up to
    match the YAML-sourced shape.
    """
    enrichment: list[PlaybookAction] = []
    immediate: list[PlaybookAction] = []
    follow_up: list[PlaybookAction] = []
    for a in (d.get("actions") or []):
        if not isinstance(a, dict):
            continue
        action_type = str(a.get("action_type") or a.get("action") or "unknown")
        kind = str(a.get("kind") or classify_kind(action_type))
        pa = PlaybookAction(
            action_type=action_type,
            target=str(a.get("target") or a.get("target_entity") or "unknown"),
            automated=bool(a.get("automated", kind == "enrichment")),
            protocol=a.get("protocol"),
            description=str(a.get("description") or ""),
            kind=kind,
        )
        if kind == "enrichment":
            enrichment.append(pa)
        elif str(a.get("priority")) == "follow_up":
            follow_up.append(pa)
        else:
            immediate.append(pa)
    return Playbook(
        narrative_id=str(d.get("name") or d.get("definition_id") or "custom"),
        playbook_name=str(d.get("name") or "custom"),
        trigger=f"custom:{d.get('name')}",
        trigger_mode=str(d.get("trigger_mode") or "auto"),
        trigger_phase=d.get("trigger_phase"),
        trigger_status=d.get("trigger_status"),
        min_confidence=float(d.get("min_confidence") or 0.0),
        trigger_detection_id=d.get("trigger_detection_id"),
        enrichment=enrichment,
        immediate=immediate,
        follow_up=follow_up,
    )


def load_narratives(narratives_path: Path) -> list[Narrative]:
    """Read every *.yaml file from the narratives directory."""
    if not narratives_path.exists():
        logger.warning("narrative_loader.dir_missing", path=str(narratives_path))
        return []

    out: list[Narrative] = []
    for f in sorted(narratives_path.glob("*.yaml")):
        try:
            data = yaml.safe_load(f.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as e:
            logger.warning("narrative_loader.parse_failed", file=str(f), error=str(e))
            continue
        if not isinstance(data, dict):
            continue

        narrative_id = str(data.get("narrative_id") or f.stem)
        name = str(data.get("name") or narrative_id)
        phases = [str(p.get("phase")) for p in data.get("phases", []) if isinstance(p, dict)]

        playbooks: list[Playbook] = []
        for pb_name, pb_node in (data.get("response_playbooks") or {}).items():
            if not isinstance(pb_node, dict):
                continue
            playbooks.append(
                _build_playbook(narrative_id, pb_name, pb_node)
            )

        out.append(
            Narrative(
                narrative_id=narrative_id,
                name=name,
                phases=phases,
                raw=data,
                playbooks=playbooks,
            )
        )
    return out


def select_playbook(
    narratives: Iterable[Narrative],
    *,
    phase: str,
    status: Optional[str] = None,
    confidence: float = 0.0,
    mode: str = "auto",
    detection_ids: Optional[list[str]] = None,
) -> Optional[Playbook]:
    """Pick the most-specific playbook matching the AttackState.

    `mode="auto"` is the pipeline path: it considers only auto-trigger
    playbooks and strictly enforces their structured conditions (phase, status,
    min_confidence, detection_id). `mode="manual"` is the on-demand path: it
    considers every playbook and matches leniently (phase only — confidence and
    status are not gates), so an analyst can run a playbook regardless of the
    attack's current confidence.
    """
    strict = mode == "auto"
    candidates: list[tuple[float, Playbook]] = []
    for n in narratives:
        # Cheap pre-filter: skip narratives that don't include this phase at all.
        if n.phases and phase not in n.phases:
            continue
        for pb in n.playbooks:
            if strict and pb.trigger_mode == "manual":
                continue  # manual-only playbooks never auto-fire
            score = _score_playbook(
                pb, phase=phase, status=status, confidence=confidence,
                strict=strict, detection_ids=detection_ids,
            )
            if score > 0:
                candidates.append((score, pb))

    if not candidates:
        return None
    candidates.sort(key=lambda x: x[0], reverse=True)
    return candidates[0][1]


def _score_playbook(
    pb: Playbook,
    *,
    phase: str,
    status: Optional[str],
    confidence: float = 0.0,
    strict: bool = True,
    detection_ids: Optional[list[str]] = None,
) -> float:
    # Structured matching when the trigger declares a phase.
    if pb.trigger_phase:
        if pb.trigger_phase.lower() != phase.lower():
            return 0.0
        if strict and confidence < pb.min_confidence:
            return 0.0
        if pb.trigger_detection_id and detection_ids is not None \
                and pb.trigger_detection_id not in detection_ids:
            return 0.0
        score = 1.0
        if pb.trigger_status:
            if status and pb.trigger_status.lower() == status.lower():
                score += 0.5
            elif strict:
                return 0.0  # auto path requires the declared status to match
        # more-specific triggers (status / detection constraints) rank higher
        if pb.trigger_detection_id:
            score += 0.25
        if pb.min_confidence:
            score += min(pb.min_confidence, 0.99) * 0.1
        return score

    # Legacy substring fallback (directly-constructed playbooks / unparseable).
    trig = pb.trigger.lower()
    score = 0.0
    if phase.lower() in trig or phase.replace("-", "_").lower() in trig \
            or phase.lower() in pb.playbook_name.lower():
        score += 1.0
    if status and status.lower() in trig:
        score += 0.5
    return score


def render_actions_for(playbook: Playbook, *, primary_host: Optional[str], primary_user: Optional[str]) -> list[dict[str, Any]]:
    """Materialize the playbook into a flat list of recommended_actions.

    Targets in YAML are abstract (e.g. 'affected_host'); we resolve them to
    the actual entity values present on the AttackState. If we can't resolve
    a target we keep the placeholder so the analyst can fill it in.
    """
    def resolve_target(token: str) -> str:
        token = token.lower()
        if "host" in token and primary_host:
            return primary_host
        if "user" in token and primary_user:
            return primary_user
        return token

    actions: list[dict[str, Any]] = []
    # Enrichment first (read-only context), then immediate, then follow_up.
    for a in playbook.enrichment:
        actions.append(a.to_response_action(priority="immediate", target_entity=resolve_target(a.target)))
    for a in playbook.immediate:
        actions.append(a.to_response_action(priority="immediate", target_entity=resolve_target(a.target)))
    for a in playbook.follow_up:
        actions.append(a.to_response_action(priority="follow_up", target_entity=resolve_target(a.target)))
    return actions
