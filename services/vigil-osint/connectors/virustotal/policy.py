"""VirusTotal connector policy. Automatable when a key is configured; the
BaseConnector.can_automate() check degrades to a deep link when it isn't."""

from __future__ import annotations

from ...connectors.base import ConnectorPolicy

POLICY = ConnectorPolicy(
    allow_automation=True,
    allow_caching=True,
    retention_days=30,
)
