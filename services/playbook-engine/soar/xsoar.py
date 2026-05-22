"""Cortex XSOAR client.

POSTs incidents to XSOAR's /incident endpoint, one per response action.
Each action type maps to a distinct XSOAR incident type so the customer's
XSOAR playbooks can route on it. Returns the XSOAR-assigned incident id.
"""

from __future__ import annotations

from typing import Any, Optional

import httpx
import structlog
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

logger = structlog.get_logger(__name__)


class XSOARError(Exception):
    pass


class XSOARRetryableError(XSOARError):
    """Raised on 5xx — tenacity retries this."""


class XSOARClient:
    def __init__(self, *, base_url: str, api_key: str, timeout: float = 10.0):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    @retry(
        retry=retry_if_exception_type((httpx.HTTPError, XSOARRetryableError)),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=8),
        reraise=True,
    )
    async def _post_incident(self, body: dict[str, Any]) -> dict[str, Any]:
        url = f"{self.base_url}/incident"
        headers = {
            "Authorization": self.api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(url, headers=headers, json=body)
        if resp.status_code >= 500:
            # Retryable.
            raise XSOARRetryableError(f"xsoar 5xx: {resp.status_code} {resp.text[:200]}")
        if resp.status_code >= 400:
            # Non-retryable client error — bubble immediately.
            raise XSOARError(f"xsoar 4xx: {resp.status_code} {resp.text[:200]}")
        try:
            return resp.json()
        except ValueError:
            return {"id": None, "raw": resp.text}

    async def _create(self, *, action: str, name: str, details: str,
                      tenant_id: str, attack_id: str) -> dict[str, Any]:
        body = {
            "type": f"VIGIL - {_pretty(action)}",
            "name": name,
            "details": details,
        }
        log = logger.bind(
            action=action, tenant_id=tenant_id, attack_id=attack_id, backend="xsoar"
        )
        log.info("soar.xsoar.dispatch.start")
        try:
            payload = await self._post_incident(body)
            log.info("soar.xsoar.dispatch.complete", incident_id=payload.get("id"))
            return {"success": True, "backend": "xsoar", "reference_id": payload.get("id")}
        except Exception as e:
            log.error("soar.xsoar.dispatch.failed", error=str(e))
            raise

    # ── action mappings ───────────────────────────────────────────────────

    async def isolate_host(self, host: str, tenant_id: str, attack_id: str) -> dict[str, Any]:
        return await self._create(
            action="isolate_host",
            name=f"Isolate {host}",
            details=f"VIGIL automated: isolate host {host}",
            tenant_id=tenant_id, attack_id=attack_id,
        )

    async def kill_process(self, process: str, host: Optional[str], tenant_id: str, attack_id: str) -> dict[str, Any]:
        target = f"{process} on {host}" if host else process
        return await self._create(
            action="kill_process",
            name=f"Kill {target}",
            details=f"VIGIL automated: kill {target}",
            tenant_id=tenant_id, attack_id=attack_id,
        )

    async def reset_credentials(self, user: str, tenant_id: str, attack_id: str) -> dict[str, Any]:
        return await self._create(
            action="reset_credentials",
            name=f"Reset credentials for {user}",
            details=f"VIGIL automated: reset credentials for {user}",
            tenant_id=tenant_id, attack_id=attack_id,
        )

    async def capture_forensic_snapshot(self, host: str, tenant_id: str, attack_id: str) -> dict[str, Any]:
        return await self._create(
            action="capture_forensic_snapshot",
            name=f"Capture snapshot of {host}",
            details=f"VIGIL automated: capture snapshot of {host}",
            tenant_id=tenant_id, attack_id=attack_id,
        )

    async def block_protocol(self, protocol: str, host: Optional[str], tenant_id: str, attack_id: str) -> dict[str, Any]:
        target = f"{protocol} from {host}" if host else protocol
        return await self._create(
            action="block_protocol",
            name=f"Block {target}",
            details=f"VIGIL automated: block {target}",
            tenant_id=tenant_id, attack_id=attack_id,
        )

    async def review_auth_logs(self, host: str, tenant_id: str, attack_id: str) -> dict[str, Any]:
        return await self._create(
            action="review_auth_logs",
            name=f"Review auth logs on {host}",
            details=f"VIGIL automated: review auth logs on {host}",
            tenant_id=tenant_id, attack_id=attack_id,
        )


def _pretty(action: str) -> str:
    return " ".join(part.capitalize() for part in action.split("_"))
