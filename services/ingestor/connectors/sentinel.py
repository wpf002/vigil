"""Microsoft Sentinel Connector

OAuth2 client-credentials flow against Azure AD; polls the Sentinel
Incidents REST API. Tokens are cached in Redis with TTL = expires_in - 60s
so a fleet of pods doesn't hammer the token endpoint.
"""

from __future__ import annotations
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


class SentinelAuthError(Exception):
    pass


class SentinelAPIError(Exception):
    pass


_AAD_LOGIN = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
_AAD_SCOPE = "https://api.loganalytics.io/.default"
_MGMT_HOST = "https://management.azure.com"
_INCIDENTS_PATH = (
    "/subscriptions/{subscription_id}"
    "/resourceGroups/{resource_group}"
    "/providers/Microsoft.OperationalInsights"
    "/workspaces/{workspace_name}"
    "/providers/Microsoft.SecurityInsights/incidents"
)
_API_VERSION = "2023-11-01"


def _severity_from(raw: Optional[str]) -> Severity:
    if not raw:
        return Severity.UNKNOWN
    s = raw.strip().lower()
    return {
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "informational": Severity.INFO,
        "info": Severity.INFO,
    }.get(s, Severity.UNKNOWN)


class SentinelConnector:
    """Polls Microsoft Sentinel Incidents.

    Redis is optional — if no client is supplied tokens are cached in-process
    only. In production the consumer should pass a redis.asyncio client so a
    multi-pod ingestor shares the access token across replicas.
    """

    def __init__(
        self,
        *,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        subscription_id: str,
        resource_group: str,
        workspace_name: str,
        redis_client: Optional[Any] = None,
        timeout: int = 30,
    ):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.subscription_id = subscription_id
        self.resource_group = resource_group
        self.workspace_name = workspace_name
        self.redis = redis_client
        self.timeout = timeout
        self._client: Optional[httpx.AsyncClient] = None
        self._token: Optional[str] = None
        self._token_expires_at: float = 0.0

    @property
    def token_cache_key(self) -> str:
        return f"sentinel:token:{self.tenant_id}"

    async def connect(self) -> None:
        self._client = httpx.AsyncClient(timeout=self.timeout)

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
    async def _fetch_token(self) -> tuple[str, int]:
        """Fetch a new access token via client_credentials. Returns
        (token, expires_in_seconds)."""
        url = _AAD_LOGIN.format(tenant_id=self.tenant_id)
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "grant_type": "client_credentials",
            "scope": _AAD_SCOPE,
        }
        try:
            resp = await self._client.post(url, data=data)
            resp.raise_for_status()
        except httpx.HTTPStatusError as e:
            raise SentinelAuthError(
                f"AAD token endpoint returned {e.response.status_code}"
            ) from e

        body = resp.json()
        token = body.get("access_token")
        expires_in = int(body.get("expires_in", 3600))
        if not token:
            raise SentinelAuthError("AAD response missing access_token")
        return token, expires_in

    async def _get_token(self, force_refresh: bool = False) -> str:
        """Read from Redis if available, otherwise fetch."""
        now = datetime.now(timezone.utc).timestamp()
        if not force_refresh and self._token and now < self._token_expires_at:
            return self._token

        if not force_refresh and self.redis is not None:
            try:
                cached = await self.redis.get(self.token_cache_key)
                if cached:
                    token = cached.decode() if isinstance(cached, (bytes, bytearray)) else str(cached)
                    self._token = token
                    # Best-effort: trust the Redis TTL more than our local clock.
                    self._token_expires_at = now + 300
                    return token
            except Exception as e:
                logger.warning("sentinel.redis_get_failed", error=str(e))

        token, expires_in = await self._fetch_token()
        ttl = max(expires_in - 60, 60)
        self._token = token
        self._token_expires_at = now + ttl
        if self.redis is not None:
            try:
                await self.redis.setex(self.token_cache_key, ttl, token)
            except Exception as e:
                logger.warning("sentinel.redis_setex_failed", error=str(e))
        logger.info("sentinel.token.refreshed", ttl=ttl)
        return token

    async def _request(self, method: str, url: str, **kwargs) -> httpx.Response:
        """Authorized request that retries once with a forced token refresh
        on 401. Other errors bubble up as SentinelAPIError."""
        if self._client is None:
            raise SentinelAPIError("Connector not connected — call connect() first")

        token = await self._get_token()
        headers = kwargs.pop("headers", {})
        headers["Authorization"] = f"Bearer {token}"
        resp = await self._client.request(method, url, headers=headers, **kwargs)

        if resp.status_code == 401:
            # Token may have been revoked — fetch a fresh one and retry once.
            logger.info("sentinel.token.refresh_on_401")
            token = await self._get_token(force_refresh=True)
            headers["Authorization"] = f"Bearer {token}"
            resp = await self._client.request(method, url, headers=headers, **kwargs)

        if resp.status_code >= 400:
            raise SentinelAPIError(
                f"Sentinel API {method} {url} returned {resp.status_code}: {resp.text[:200]}"
            )
        return resp

    async def get_incidents(
        self,
        *,
        since: Optional[datetime] = None,
        max_pages: int = 5,
    ) -> list[dict[str, Any]]:
        """Pull active New incidents created since `since`.

        Follows nextLink pagination up to max_pages to bound a single poll.
        Returns the raw incident dicts; caller maps to CDMEvent.
        """
        path = _INCIDENTS_PATH.format(
            subscription_id=self.subscription_id,
            resource_group=self.resource_group,
            workspace_name=self.workspace_name,
        )
        url = f"{_MGMT_HOST}{path}"

        params: dict[str, str] = {
            "api-version": _API_VERSION,
            "$top": "500",
        }
        if since is not None:
            iso = since.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            params["$filter"] = (
                f"properties/status eq 'New' and properties/createdTimeUtc ge {iso}"
            )
        else:
            params["$filter"] = "properties/status eq 'New'"

        incidents: list[dict[str, Any]] = []
        next_url: Optional[str] = url
        next_params: Optional[dict[str, str]] = params
        pages = 0
        while next_url and pages < max_pages:
            resp = await self._request("GET", next_url, params=next_params)
            body = resp.json()
            incidents.extend(body.get("value", []))
            next_url = body.get("nextLink")
            next_params = None  # nextLink already includes query.
            pages += 1
        logger.info("sentinel.incidents.polled", count=len(incidents), pages=pages)
        return incidents

    def map_incident(self, incident: dict[str, Any], tenant_id: str) -> CDMEvent:
        """Map a raw Sentinel incident to a CDMEvent."""
        props = incident.get("properties", {}) or {}
        title = props.get("title") or "Sentinel incident"
        severity = _severity_from(props.get("severity"))

        created = props.get("createdTimeUtc")
        ts = _parse_iso(created) if created else datetime.now(timezone.utc)

        rule_name = title
        product_names = props.get("alertProductNames") or []
        if isinstance(product_names, list) and product_names:
            rule_name = product_names[0] or title

        mitre: Optional[MITREMapping] = None
        additional = props.get("additionalData") or {}
        tactics = additional.get("tactics") or []
        if isinstance(tactics, list) and tactics:
            mitre = MITREMapping(tactic=str(tactics[0]))

        return CDMEvent(
            tenant_id=tenant_id,
            source_event_id=str(incident.get("name") or incident.get("id") or ""),
            source_siem="sentinel",
            timestamp=ts,
            category=EventCategory.UNKNOWN,
            severity=severity,
            status=AlertStatus.NEW,
            title=title,
            rule_name=rule_name,
            rule_id=str(props.get("incidentNumber") or ""),
            mitre=mitre,
            raw_event=incident,
        )

    async def health_check(self) -> bool:
        """Best-effort: token fetch succeeds → considered healthy."""
        try:
            await self._get_token()
            return True
        except Exception as e:
            logger.warning("sentinel.health_check.failed", error=str(e))
            return False


def _parse_iso(value: str) -> datetime:
    """Parse an ISO 8601 string. Falls back to now() on parse failure so
    a malformed timestamp doesn't break a whole poll cycle."""
    try:
        # Sentinel sometimes returns Z, sometimes +00:00, occasionally 7-digit fractions.
        cleaned = value.rstrip("Z")
        if "." in cleaned:
            head, frac = cleaned.split(".", 1)
            cleaned = f"{head}.{frac[:6]}"
        cleaned = cleaned + "+00:00" if "+" not in cleaned and "-" not in cleaned[10:] else cleaned
        return datetime.fromisoformat(cleaned).astimezone(timezone.utc)
    except Exception:
        return datetime.now(timezone.utc)
