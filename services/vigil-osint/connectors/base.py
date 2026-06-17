"""Abstract connector interface + per-connector policy.

Contract: translate(query) -> execute(provider_query, auth) -> normalize(raw)
-> list[Observation]. Auth/API keys come from the environment only.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from ..models.observation import Observation
from ..uql.parser import UQLQuery


@dataclass
class ConnectorPolicy:
    """Governs how/whether a connector may be invoked automatically."""
    allow_automation: bool = True   # if False, return a deep_link instead of executing
    allow_caching: bool = True
    retention_days: int = 30


class BaseConnector(ABC):
    name: str = "base"
    category: str = "recon"          # recon | threat_intel | leak | web | cert
    auth_type: str = "none"          # none | api_key | oauth
    capabilities: list[str] = []     # entity types this connector supports
    policy: ConnectorPolicy = ConnectorPolicy()

    @abstractmethod
    def translate(self, query: UQLQuery) -> dict[str, Any]:
        """Map a parsed UQL query into this provider's request shape."""

    @abstractmethod
    def execute(self, provider_query: dict[str, Any], auth: dict[str, Any]) -> dict[str, Any]:
        """Call the provider (sync for MVP). Returns the raw payload."""

    @abstractmethod
    def normalize(self, raw: dict[str, Any]) -> list[Observation]:
        """Normalize the raw payload into canonical Observations."""

    def supports(self, entity_type: str) -> bool:
        return entity_type in self.capabilities

    def deep_link_for(self, query: UQLQuery) -> str:
        """Human-facing link used when automation is disallowed. Override if the
        provider has a nicer UI URL."""
        return ""
