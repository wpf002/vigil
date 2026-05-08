"""ATT&CK coverage report.

Pure function over the detection_versions table contents — no SQL access
beyond what the caller provides. Centralised so /coverage stays small.
"""

from __future__ import annotations
from typing import Any


# 14 MITRE ATT&CK Enterprise tactics. Match strings used elsewhere in the
# codebase (lower-kebab-case, see services/attack-state-engine/models/attack_state.py
# MITRETactic enum values).
MITRE_TACTICS: list[str] = [
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
]


def build_coverage_report(active_detections: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute coverage given the list of active detection_versions rows.

    Each row should expose att_ck_tactic and detection_id.
    """
    by_tactic: dict[str, list[str]] = {t: [] for t in MITRE_TACTICS}
    unmapped: list[str] = []

    for det in active_detections:
        tactic = det.get("att_ck_tactic")
        detection_id = det.get("detection_id")
        if tactic in by_tactic and detection_id is not None:
            by_tactic[tactic].append(detection_id)
        elif detection_id is not None:
            unmapped.append(detection_id)

    counts = {t: len(d) for t, d in by_tactic.items()}
    covered_tactics = [t for t, n in counts.items() if n > 0]
    uncovered = [t for t in MITRE_TACTICS if t not in covered_tactics]
    score = round(len(covered_tactics) / len(MITRE_TACTICS), 4)

    return {
        "total_detections": sum(counts.values()) + len(unmapped),
        "tactics": MITRE_TACTICS,
        "counts_by_tactic": counts,
        "detections_by_tactic": by_tactic,
        "covered_tactics": covered_tactics,
        "uncovered_tactics": uncovered,
        "coverage_score": score,
        "unmapped_detections": unmapped,
    }
