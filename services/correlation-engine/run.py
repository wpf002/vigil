"""
Launcher for the correlation engine.

Registers the hyphenated sibling dirs as importable Python packages
(``attack_state_engine``, ``ingestor``, ``correlation_engine``) and
hands off to uvicorn.
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
    spec = importlib.util.spec_from_file_location(
        alias,
        pkg_path / "__init__.py",
        submodule_search_locations=[str(pkg_path)],
    )
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot register {alias}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[alias] = mod
    spec.loader.exec_module(mod)


_register("attack_state_engine", _SERVICES / "attack-state-engine")
_register("ingestor", _SERVICES / "ingestor")
_register("correlation_engine", _HERE)

import uvicorn  # noqa: E402
from correlation_engine.config import get_config  # noqa: E402

if __name__ == "__main__":
    cfg = get_config()
    uvicorn.run(
        "correlation_engine.main:app",
        host="0.0.0.0",
        port=cfg.port,
        reload=False,
        log_level=cfg.log_level.lower(),
    )
