"""urlscan connector policy. Passive search is safe to automate and cache."""

from __future__ import annotations

from ...connectors.base import ConnectorPolicy

POLICY = ConnectorPolicy(
    allow_automation=True,
    allow_caching=True,
    retention_days=30,
)
