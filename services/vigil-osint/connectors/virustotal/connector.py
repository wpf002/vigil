"""VirusTotal v3 connector.

API key comes from the VIRUSTOTAL_API_KEY environment variable ONLY. When it is
unset the connector cannot automate (see BaseConnector.can_automate) and the
router returns a deep link to the VT web UI instead of calling out.

Endpoints (header: x-apikey):
    ip     GET /api/v3/ip_addresses/{ip}
    domain GET /api/v3/domains/{domain}
    url    GET /api/v3/urls/{base64url(url)}
    hash   GET /api/v3/files/{hash}
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone
from typing import Any

import httpx

from ...config import get_config
from ...connectors.base import BaseConnector
from ...models.observation import Observation, TLP
from ...uql.parser import UQLQuery
from .policy import POLICY


def _vt_url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


class VirusTotalConnector(BaseConnector):
    name = "virustotal"
    homepage = "https://www.virustotal.com"
    category = "threat_intel"
    auth_type = "api_key"
    api_key_env = "VIRUSTOTAL_API_KEY"
    capabilities = ["ip", "domain", "url", "hash"]
    policy = POLICY

    def _path(self, query: UQLQuery) -> str:
        if query.type == "ip":
            return f"/api/v3/ip_addresses/{query.value}"
        if query.type == "domain":
            return f"/api/v3/domains/{query.value}"
        if query.type == "url":
            return f"/api/v3/urls/{_vt_url_id(query.value)}"
        if query.type == "hash":
            return f"/api/v3/files/{query.value}"
        return ""

    def translate(self, query: UQLQuery) -> dict[str, Any]:
        return {
            "path": self._path(query),
            "entity_type": query.type,
            "entity_value": query.value,
        }

    def execute(self, provider_query: dict[str, Any], auth: dict[str, Any]) -> dict[str, Any]:
        cfg = get_config()
        url = f"{cfg.virustotal_base_url.rstrip('/')}{provider_query['path']}"
        with httpx.Client(timeout=cfg.http_timeout_seconds) as client:
            resp = client.get(url, headers={"x-apikey": self.api_key() or ""})
            resp.raise_for_status()
            body = resp.json()
        body["_query"] = provider_query
        return body

    def normalize(self, raw: dict[str, Any]) -> list[Observation]:
        ctx = raw.get("_query", {})
        entity_type = ctx.get("entity_type", "")
        entity_value = ctx.get("entity_value", "")
        attrs = (raw.get("data") or {}).get("attributes") or {}
        stats = attrs.get("last_analysis_stats") or {}
        malicious = int(stats.get("malicious") or 0)
        suspicious = int(stats.get("suspicious") or 0)
        harmless = int(stats.get("harmless") or 0)
        undetected = int(stats.get("undetected") or 0)

        if malicious > 0:
            confidence = 0.9
        elif suspicious > 0:
            confidence = 0.6
        else:
            confidence = 0.5

        return [Observation(
            source=self.name,
            entity_type=entity_type,
            entity_value=entity_value,
            observed_at=None,
            retrieved_at=datetime.now(timezone.utc).isoformat(),
            confidence_score=confidence,
            tlp=TLP.WHITE.value,
            summary={
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "undetected": undetected,
                "reputation": attrs.get("reputation"),
                "verdict": "malicious" if malicious else ("suspicious" if suspicious else "clean"),
            },
            raw=raw.get("data") or {},
            deep_link=self.deep_link_for(UQLQuery(type=entity_type, value=entity_value, raw=entity_value)),
        )]

    def deep_link_for(self, query: UQLQuery) -> str:
        base = f"{get_config().virustotal_base_url.rstrip('/')}/gui"
        if query.type == "ip":
            return f"{base}/ip-address/{query.value}"
        if query.type == "domain":
            return f"{base}/domain/{query.value}"
        if query.type == "url":
            return f"{base}/url/{_vt_url_id(query.value)}"
        if query.type == "hash":
            return f"{base}/file/{query.value}"
        return f"{base}/search?query={query.value}"
