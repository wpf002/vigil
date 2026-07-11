"""Abstract connector interface + per-connector policy.

Contract: translate(query) -> execute(provider_query, auth) -> normalize(raw)
-> list[Observation]. Auth/API keys come from the environment only.
"""

from __future__ import annotations

import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Optional

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
    # Name of the env var holding this connector's API key (keys are NEVER in
    # code/config — env only). None for keyless connectors.
    api_key_env: Optional[str] = None
    homepage: str = ""               # provider site, shown/linked in Settings

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

    def api_key(self) -> Optional[str]:
        """The connector's API key from the environment, or None."""
        return os.getenv(self.api_key_env) if self.api_key_env else None

    def can_automate(self) -> bool:
        """Whether the router may execute this connector automatically.

        False when policy forbids it, OR when it needs an API key that isn't
        configured — in which case the router hands back a deep_link instead of
        calling out. This is how a keyless VirusTotal (etc.) degrades gracefully.
        """
        if not self.policy.allow_automation:
            return False
        if self.auth_type == "api_key" and not self.api_key():
            return False
        return True

    def automation_block_reason(self) -> str:
        if not self.policy.allow_automation:
            return "automation_disabled_by_policy"
        if self.auth_type == "api_key" and not self.api_key():
            return "api_key_not_configured"
        return ""

    def deep_link_for(self, query: UQLQuery) -> str:
        """Human-facing link used when automation is disallowed. Override if the
        provider has a nicer UI URL."""
        return ""
