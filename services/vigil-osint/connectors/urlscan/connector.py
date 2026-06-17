"""urlscan.io connector — passive search only (no active scan).

Passive search needs no auth on the public endpoint:
    GET https://urlscan.io/api/v1/search/?q={query}   (120 req/min public)
Active scanning (POST /scan) is intentionally NOT implemented.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import httpx

from ...config import get_config
from ...connectors.base import BaseConnector
from ...models.observation import Observation, TLP
from ...uql.parser import UQLQuery
from .policy import POLICY

# Map a UQL entity type -> the urlscan search field.
_FIELD = {
    "domain": "page.domain",
    "ip": "page.ip",
    "url": "page.url",
    "hash": "hash",
    "email": "page.url",   # urlscan has no email field; best-effort substring match
}


class UrlscanConnector(BaseConnector):
    name = "urlscan"
    category = "web"
    auth_type = "none"
    capabilities = ["domain", "ip", "url", "hash", "keyword"]
    policy = POLICY

    # ── translate ──────────────────────────────────────────────────────────
    def translate(self, query: UQLQuery) -> dict[str, Any]:
        field = _FIELD.get(query.type)
        if field is None or query.type == "keyword":
            q = query.value
        elif field == "hash":
            q = f"hash:{query.value}"
        else:
            q = f'{field}:"{query.value}"'
        return {"q": q, "entity_type": query.type, "entity_value": query.value}

    # ── execute (sync) ─────────────────────────────────────────────────────
    def execute(self, provider_query: dict[str, Any], auth: dict[str, Any]) -> dict[str, Any]:
        cfg = get_config()
        url = f"{cfg.urlscan_base_url.rstrip('/')}/api/v1/search/"
        with httpx.Client(timeout=cfg.http_timeout_seconds) as client:
            resp = client.get(url, params={"q": provider_query["q"]})
            resp.raise_for_status()
            body = resp.json()
        # carry the query context through for normalize()
        body["_query"] = provider_query
        return body

    # ── normalize ──────────────────────────────────────────────────────────
    def normalize(self, raw: dict[str, Any]) -> list[Observation]:
        cfg = get_config()
        ctx = raw.get("_query", {})
        entity_type = ctx.get("entity_type", "domain")
        entity_value = ctx.get("entity_value", "")
        retrieved = datetime.now(timezone.utc).isoformat()

        observations: list[Observation] = []
        for result in (raw.get("results") or [])[: cfg.max_observations_per_connector]:
            page = result.get("page") or {}
            stats = result.get("stats") or {}
            task = result.get("task") or {}
            malicious = bool(stats.get("malicious"))
            observations.append(Observation(
                source=self.name,
                entity_type=entity_type,
                entity_value=entity_value,
                observed_at=task.get("time"),
                retrieved_at=retrieved,
                confidence_score=0.9 if malicious else 0.7,
                tlp=TLP.WHITE.value,
                summary={
                    "url": page.get("url"),
                    "ip": page.get("ip"),
                    "asn": page.get("asn"),
                    "country": page.get("country"),
                    "malicious": malicious,
                    "screenshot_url": result.get("screenshot"),
                },
                raw=result,
                deep_link=None,
            ))
        return observations

    def deep_link_for(self, query: UQLQuery) -> str:
        field = _FIELD.get(query.type, "")
        q = f'{field}:"{query.value}"' if field and query.type != "keyword" else query.value
        return f"{get_config().urlscan_base_url.rstrip('/')}/search/#{q}"
