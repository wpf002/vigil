"""URLVoid / IPVoid connector — deep-link only.

No free query API, so policy.allow_automation is False and the router returns a
deep link to the provider's reputation report. execute()/normalize() exist to
satisfy the interface but are never invoked while automation is disabled.
"""

from __future__ import annotations

from typing import Any

from ...connectors.base import BaseConnector
from ...models.observation import Observation
from ...uql.parser import UQLQuery
from .policy import POLICY


class UrlVoidConnector(BaseConnector):
    name = "urlvoid"
    homepage = "https://www.urlvoid.com"
    category = "threat_intel"
    auth_type = "none"
    capabilities = ["domain", "url", "ip"]
    policy = POLICY

    def translate(self, query: UQLQuery) -> dict[str, Any]:
        return {"entity_type": query.type, "entity_value": query.value}

    def execute(self, provider_query: dict[str, Any], auth: dict[str, Any]) -> dict[str, Any]:
        # Never called: policy disables automation.
        raise NotImplementedError("urlvoid is deep-link only")

    def normalize(self, raw: dict[str, Any]) -> list[Observation]:
        return []

    def deep_link_for(self, query: UQLQuery) -> str:
        if query.type == "ip":
            return f"https://www.ipvoid.com/ip-blacklist-check/#{query.value}"
        # domain/url → strip scheme/path to a host for the URLVoid scan path.
        host = query.value
        if "://" in host:
            host = host.split("://", 1)[1]
        host = host.split("/", 1)[0]
        return f"https://www.urlvoid.com/scan/{host}/"
