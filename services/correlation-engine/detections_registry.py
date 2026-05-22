"""Detection registry — maps detection_id → state_impact metadata.

Loads from detections/compiled/manifest.json (written by services/signal-translation).
Falls back to a hardcoded D1–D4 dict if the manifest is missing — so the
correlation engine still works in environments where the compiler hasn't
run yet (e.g. fresh checkouts, ad-hoc tests).
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from threading import Lock
from typing import Optional, TypedDict

import structlog

from ._compat import MITRETactic, PhaseStatus

logger = structlog.get_logger(__name__)


class StateImpact(TypedDict):
    transitions_to: MITRETactic
    status: PhaseStatus
    confidence_contribution: float
    progression: bool


# ── fallback registry (used when manifest.json is missing) ──────────────────

_FALLBACK: dict[str, StateImpact] = {
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


# ── manifest loading ────────────────────────────────────────────────────────

_REPO_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_MANIFEST = _REPO_ROOT / "detections" / "compiled" / "manifest.json"

_lock = Lock()
_registry: dict[str, StateImpact] = {}
_loaded_from: str = "unloaded"


def _manifest_path() -> Path:
    override = os.getenv("DETECTIONS_MANIFEST_PATH")
    return Path(override) if override else _DEFAULT_MANIFEST


def _load_from_manifest(path: Path) -> Optional[dict[str, StateImpact]]:
    if not path.exists():
        return None
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        logger.warning("detections_registry.manifest_unreadable", error=str(e))
        return None

    out: dict[str, StateImpact] = {}
    for detection_id, entry in manifest.items():
        si = (entry or {}).get("state_impact") or {}
        try:
            out[detection_id.upper()] = {
                "transitions_to": MITRETactic(si["transitions_to"]),
                "status": PhaseStatus(si["status"]),
                "confidence_contribution": float(si["confidence_contribution"]),
                "progression": bool(si.get("progression", False)),
            }
        except (KeyError, ValueError, TypeError) as e:
            logger.warning(
                "detections_registry.manifest_entry_skipped",
                detection_id=detection_id,
                error=str(e),
            )
    return out


def reload() -> str:
    """Re-read the manifest. Falls back to the hardcoded dict on miss.
    Returns a short tag describing the source ("manifest" | "fallback").
    """
    global _registry, _loaded_from
    with _lock:
        loaded = _load_from_manifest(_manifest_path())
        if loaded:
            _registry = loaded
            _loaded_from = "manifest"
        else:
            _registry = dict(_FALLBACK)
            _loaded_from = "fallback"
        logger.info(
            "detections_registry.loaded",
            source=_loaded_from,
            count=len(_registry),
        )
        return _loaded_from


# Eager load on import so legacy callers using lookup() see the manifest
# without having to call reload() first.
reload()


def lookup(detection_id: Optional[str]) -> Optional[StateImpact]:
    if not detection_id:
        return None
    return _registry.get(detection_id.upper())


def loaded_source() -> str:
    """Returns 'manifest' or 'fallback' — useful for diagnostics."""
    return _loaded_from


def normalize_event_state_impact(state_impact_raw: Optional[dict]) -> Optional[StateImpact]:
    """Coerce a raw dict (from CDMEvent.state_impact, parsed from YAML) into
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
