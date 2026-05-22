"""Test bootstrap for detection-engine.

Registers the hyphenated directory as the importable Python package
``detection_engine`` so test modules can use absolute imports.
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


_register("detection_engine", _HERE)
