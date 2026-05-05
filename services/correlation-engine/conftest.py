"""
Test bootstrap for correlation-engine.

Triggers the cross-service import bridge in ``_compat.py`` so the test
suite can import ``correlation_engine`` and the sibling packages
(``attack_state_engine``, ``ingestor``) under valid Python aliases.
"""

from __future__ import annotations
import importlib.util
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_SERVICES = _HERE.parent


def _register(alias: str, pkg_path: Path) -> None:
    if alias in sys.modules:
        return
    init_py = pkg_path / "__init__.py"
    spec = importlib.util.spec_from_file_location(
        alias,
        init_py,
        submodule_search_locations=[str(pkg_path)],
    )
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load {alias} from {pkg_path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[alias] = mod
    spec.loader.exec_module(mod)


# Sibling packages first — _compat.py expects these to be loadable.
_register("attack_state_engine", _SERVICES / "attack-state-engine")
_register("ingestor", _SERVICES / "ingestor")
# Then the correlation-engine itself, so tests can use absolute imports.
_register("correlation_engine", _HERE)
