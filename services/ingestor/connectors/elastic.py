"""Elastic Connector

Polls the .alerts-security.alerts-default index using API key auth. Maps
each Kibana detection-rule alert to a CDMEvent.
"""

from __future__ import annotations
import base64
from datetime import datetime, timezone
from typing import Any, Optional

import httpx
import structlog
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from ..models.cdm import (
    AlertStatus,
    CDMEvent,
    EventCategory,
    MITREMapping,
    Severity,
)

logger = structlog.get_logger(__name__)


class ElasticAuthError(Exception):
    pass


class ElasticAPIError(Exception):
    pass


_ALERTS_INDEX = ".alerts-security.alerts-default"


def _severity_from(raw: Any) -> Severity:
    if raw is None:
        return Severity.UNKNOWN
    s = str(raw).strip().lower()
    return {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "informational": Severity.INFO,
        "info": Severity.INFO,
    }.get(s, Severity.UNKNOWN)


class ElasticConnector:
    def __init__(
        self,
        *,
        url: str,
        api_key_id: str,
        api_key_secret: str,
        timeout: int = 30,
        verify_ssl: bool = True,
    ):
        self.url = url.rstrip("/")
        self.api_key_id = api_key_id
        self.api_key_secret = api_key_secret
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self._client: Optional[httpx.AsyncClient] = None

    @property
    def auth_header(self) -> str:
        # Elastic accepts ApiKey base64(id:secret).
        token = base64.b64encode(
            f"{self.api_key_id}:{self.api_key_secret}".encode("utf-8")
        ).decode("ascii")
        return f"ApiKey {token}"

    async def connect(self) -> None:
        self._client = httpx.AsyncClient(
            timeout=self.timeout,
            verify=self.verify_ssl,
            headers={
                "Content-Type": "application/json",
                "Authorization": self.auth_header,
            },
        )

    async def disconnect(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    async def __aenter__(self):
        await self.connect()
        return self

    async def __aexit__(self, *args):
        await self.disconnect()

    @retry(
        retry=retry_if_exception_type(httpx.HTTPError),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
    )
    async def get_active_alerts(
        self,
        *,
        since: Optional[datetime] = None,
        size: int = 500,
    ) -> list[dict[str, Any]]:
        """Search the alerts index for active alerts since `since`."""
        if self._client is None:
            raise ElasticAPIError("Connector not connected — call connect() first")

        gte = (
            since.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            if since is not None
            else "now-15m"
        )
        body = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"kibana.alert.status": "active"}},
                        {"range": {"@timestamp": {"gte": gte}}},
                    ]
                }
            },
            "size": size,
            "sort": [{"@timestamp": {"order": "asc"}}],
        }
        url = f"{self.url}/{_ALERTS_INDEX}/_search"
        resp = await self._client.post(url, json=body)
        if resp.status_code == 401:
            raise ElasticAuthError("Elastic returned 401 — check API key")
        if resp.status_code >= 400:
            raise ElasticAPIError(
                f"Elastic _search returned {resp.status_code}: {resp.text[:200]}"
            )
        body = resp.json()
        hits = (body.get("hits") or {}).get("hits") or []
        logger.info("elastic.alerts.polled", count=len(hits))
        return hits

    def map_alert(self, hit: dict[str, Any], tenant_id: str) -> CDMEvent:
        """Map an Elastic alert hit to a CDMEvent."""
        src = hit.get("_source") or {}
        rule_name = src.get("kibana.alert.rule.name") or _nested(src, "kibana", "alert", "rule", "name") or "Elastic alert"
        rule_uuid = src.get("kibana.alert.rule.uuid") or _nested(src, "kibana", "alert", "rule", "uuid")
        severity_raw = src.get("kibana.alert.severity") or _nested(src, "kibana", "alert", "severity")
        severity = _severity_from(severity_raw)
        ts_raw = src.get("@timestamp") or src.get("timestamp")
        ts = _parse_iso(ts_raw) if ts_raw else datetime.now(timezone.utc)

        # threat is normally an array of objects; tolerate missing.
        threat = src.get("threat") or []
        if not isinstance(threat, list):
            threat = []
        first_threat = threat[0] if threat else {}
        techniques = first_threat.get("technique") or []
        first_technique = techniques[0] if isinstance(techniques, list) and techniques else {}
        tactic = (first_threat.get("tactic") or {}).get("name") if isinstance(first_threat.get("tactic"), dict) else None
        technique_id = first_technique.get("id") if isinstance(first_technique, dict) else None

        mitre: Optional[MITREMapping] = None
        if tactic or technique_id:
            mitre = MITREMapping(tactic=tactic, technique_id=technique_id)

        return CDMEvent(
            tenant_id=tenant_id,
            source_event_id=str(hit.get("_id") or ""),
            source_siem="elastic",
            timestamp=ts,
            category=EventCategory.UNKNOWN,
            severity=severity,
            status=AlertStatus.NEW,
            title=str(rule_name),
            rule_name=str(rule_name),
            rule_id=str(rule_uuid) if rule_uuid else None,
            mitre=mitre,
            raw_event=src,
        )

    async def health_check(self) -> bool:
        if self._client is None:
            return False
        try:
            resp = await self._client.get(f"{self.url}/")
            return resp.status_code == 200
        except Exception as e:
            logger.warning("elastic.health_check.failed", error=str(e))
            return False


def _nested(d: dict[str, Any], *keys: str) -> Any:
    cur: Any = d
    for k in keys:
        if not isinstance(cur, dict) or k not in cur:
            return None
        cur = cur[k]
    return cur


def _parse_iso(value: str) -> datetime:
    try:
        cleaned = value.rstrip("Z")
        if "." in cleaned:
            head, frac = cleaned.split(".", 1)
            cleaned = f"{head}.{frac[:6]}"
        cleaned = cleaned + "+00:00" if "+" not in cleaned and "-" not in cleaned[10:] else cleaned
        return datetime.fromisoformat(cleaned).astimezone(timezone.utc)
    except Exception:
        return datetime.now(timezone.utc)
