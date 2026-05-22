"""
Cross-service import bridge.

The correlation engine depends on the AttackState model + store from the
attack-state-engine and the CDM model from the ingestor. Their directories
contain hyphens — not directly importable via Python's ``import`` syntax —
so this module registers them under valid aliases (``attack_state_engine``,
``ingestor``) before re-exporting the symbols the rest of the service uses.
The conftest used by pytest performs the same registration at test collection
time, so this module is safe to load under either runtime.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_SERVICES = _HERE.parent


def _register_pkg(alias: str, dir_name: str) -> None:
    if alias in sys.modules:
        return
    pkg_path = _SERVICES / dir_name
    init_py = pkg_path / "__init__.py"
    if not init_py.exists():
        raise ImportError(f"Cannot bridge {dir_name}: missing __init__.py at {init_py}")
    spec = importlib.util.spec_from_file_location(
        alias,
        init_py,
        submodule_search_locations=[str(pkg_path)],
    )
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot create spec for {alias}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[alias] = mod
    spec.loader.exec_module(mod)


_register_pkg("attack_state_engine", "attack-state-engine")
_register_pkg("ingestor", "ingestor")


from attack_state_engine.engine.confidence import (  # noqa: E402
    ESCALATION_THRESHOLD,
    PHASE_ORDER,
    ConfidenceEngine,
)

# Re-export the symbols the rest of the service needs.
from attack_state_engine.models.attack_state import (  # noqa: E402
    AttackState,
    AttackStateStatus,
    AttackStateTransition,
    EvidenceItem,
    ImpactLevel,
    MITRETactic,
    Momentum,
    PhaseState,
    PhaseStatus,
    ResponseAction,
)
from attack_state_engine.store import AttackStateStore  # noqa: E402
from ingestor.models.cdm import CDMEvent  # noqa: E402

__all__ = [
    "AttackState",
    "AttackStateStatus",
    "AttackStateTransition",
    "AttackStateStore",
    "CDMEvent",
    "ConfidenceEngine",
    "ESCALATION_THRESHOLD",
    "EvidenceItem",
    "ImpactLevel",
    "MITRETactic",
    "Momentum",
    "PhaseState",
    "PhaseStatus",
    "PHASE_ORDER",
    "ResponseAction",
]
