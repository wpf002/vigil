"""Loads attack-narrative YAML templates and resolves the playbook to run.

Each narrative has a `response_playbooks` map keyed by playbook_name. The
key encodes the trigger via convention (e.g. credential_access_confirmed),
but the authoritative trigger is the `trigger:` string. We match against
phase + status by simple substring inclusion — sufficient for the curated
narrative library we ship today.
"""

from __future__ import annotations

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
    trigger: str
    enrichment: list[PlaybookAction] = field(default_factory=list)
    immediate: list[PlaybookAction] = field(default_factory=list)
    follow_up: list[PlaybookAction] = field(default_factory=list)


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
                Playbook(
                    narrative_id=narrative_id,
                    playbook_name=pb_name,
                    trigger=str(pb_node.get("trigger") or ""),
                    enrichment=[_load_action(a, force_kind="enrichment")
                                for a in (pb_node.get("enrichment") or []) if isinstance(a, dict)],
                    immediate=[_load_action(a) for a in (pb_node.get("immediate") or []) if isinstance(a, dict)],
                    follow_up=[_load_action(a) for a in (pb_node.get("follow_up") or []) if isinstance(a, dict)],
                )
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
) -> Optional[Playbook]:
    """Pick the most-specific playbook matching the AttackState.

    Strategy: a playbook matches if its trigger string contains the phase
    name; status (if known) further narrows the choice. Among matches we
    prefer ones that mention 'Confirmed' status when status is Confirmed.
    Higher confidence-threshold matches beat lower ones.
    """
    candidates: list[tuple[float, Playbook]] = []
    for n in narratives:
        # Cheap pre-filter: skip narratives that don't include this phase at all.
        if n.phases and phase not in n.phases:
            continue
        for pb in n.playbooks:
            score = _score_playbook(pb, phase=phase, status=status)
            if score > 0:
                candidates.append((score, pb))

    if not candidates:
        return None
    candidates.sort(key=lambda x: x[0], reverse=True)
    return candidates[0][1]


def _score_playbook(pb: Playbook, *, phase: str, status: Optional[str]) -> float:
    trig = pb.trigger.lower()
    score = 0.0
    if phase.lower() in trig or phase.replace("-", "_").lower() in trig or phase.lower() in pb.playbook_name.lower():
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
