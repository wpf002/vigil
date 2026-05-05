"""
Test bootstrap for attack-state-engine.

Registers this hyphenated directory as the importable Python package
``attack_state_engine`` so test modules can use absolute imports
(`from attack_state_engine.models.attack_state import ...`) and so the
existing relative imports inside ``engine/`` and ``store.py`` resolve
through the canonical package name.
"""

from __future__ import annotations
import importlib.util
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent


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


_register("attack_state_engine", _HERE)
