"""Connector registry — auto-discovers connectors under connectors/.

Scans each subdirectory containing a connector.py, imports it, instantiates the
BaseConnector subclass, and registers it by name. Routing checks that a
connector's capabilities cover the requested entity type before invoking it.
"""

from __future__ import annotations

import importlib
import inspect
from pathlib import Path
from typing import Optional

import structlog

from .base import BaseConnector

logger = structlog.get_logger(__name__)


class ConnectorRegistry:
    def __init__(self) -> None:
        self._connectors: dict[str, BaseConnector] = {}

    def discover(self) -> None:
        base_dir = Path(__file__).resolve().parent
        for sub in sorted(base_dir.iterdir()):
            if not sub.is_dir() or not (sub / "connector.py").exists():
                continue
            module_name = f"{__package__}.{sub.name}.connector"
            try:
                mod = importlib.import_module(module_name)
            except Exception as e:  # noqa: BLE001
                logger.warning("osint.registry.import_failed", module=module_name, error=str(e))
                continue
            for _, obj in inspect.getmembers(mod, inspect.isclass):
                if issubclass(obj, BaseConnector) and obj is not BaseConnector \
                        and obj.__module__ == mod.__name__:
                    inst = obj()
                    self._connectors[inst.name] = inst
                    logger.info("osint.registry.registered", connector=inst.name,
                                capabilities=inst.capabilities)

    def all(self) -> list[BaseConnector]:
        return list(self._connectors.values())

    def get(self, name: str) -> Optional[BaseConnector]:
        return self._connectors.get(name)

    def capable(self, entity_type: str, requested: Optional[list[str]] = None) -> list[BaseConnector]:
        """Connectors that support `entity_type`, optionally filtered to a
        requested subset (empty/None = all capable connectors)."""
        wanted = set(requested) if requested else None
        return [
            c for c in self._connectors.values()
            if c.supports(entity_type) and (wanted is None or c.name in wanted)
        ]


registry = ConnectorRegistry()
