"""URLVoid/IPVoid policy — deep-link only.

URLVoid (APIVoid) has no free query API, so automation is disabled: the router
always returns a link to the provider's web reputation report rather than
calling out. Flip allow_automation to True and add an execute() path if an
APIVoid key is ever configured.
"""

from __future__ import annotations

from ...connectors.base import ConnectorPolicy

POLICY = ConnectorPolicy(
    allow_automation=False,
    allow_caching=False,
    retention_days=0,
)
