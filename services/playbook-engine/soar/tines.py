"""Tines client.

Tines uses webhook triggers — one URL per action type. The mapping is
configured via env vars (TINES_WEBHOOK_*); the client looks them up at
call time. Each request includes a Bearer token plus the canonical body
the user's Tines story is expected to consume.
"""

from __future__ import annotations
from datetime import datetime, timezone
from typing import Any, Optional

import httpx
import structlog
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

logger = structlog.get_logger(__name__)


class TinesError(Exception):
    pass


class TinesRetryableError(TinesError):
    """Raised on 5xx — tenacity retries this."""


class TinesClient:
    def __init__(
        self,
        *,
        api_key: Optional[str],
        webhooks: dict[str, str],
        timeout: float = 10.0,
    ):
        self.api_key = api_key
        # action -> webhook URL.
        self.webhooks = {k: v for k, v in webhooks.items() if v}
        self.timeout = timeout

    @retry(
        retry=retry_if_exception_type((httpx.HTTPError, TinesRetryableError)),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=8),
        reraise=True,
    )
    async def _post(self, url: str, body: dict[str, Any]) -> dict[str, Any]:
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(url, headers=headers, json=body)
        if resp.status_code >= 500:
            raise TinesRetryableError(f"tines 5xx: {resp.status_code} {resp.text[:200]}")
        if resp.status_code >= 400:
            raise TinesError(f"tines 4xx: {resp.status_code} {resp.text[:200]}")
        try:
            return resp.json()
        except ValueError:
            return {"raw": resp.text}

    async def fire(
        self,
        *,
        action: str,
        target: str,
        tenant_id: str,
        attack_id: str,
        extra: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        url = self.webhooks.get(action)
        if not url:
            raise TinesError(f"No Tines webhook configured for action '{action}'")
        body = {
            "action": action,
            "target": target,
            "tenant_id": tenant_id,
            "attack_id": attack_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        if extra:
            body.update(extra)
        log = logger.bind(
            action=action, tenant_id=tenant_id, attack_id=attack_id, backend="tines"
        )
        log.info("soar.tines.dispatch.start", url_host=_safe_host(url))
        result = await self._post(url, body)
        log.info("soar.tines.dispatch.complete")
        return {"success": True, "backend": "tines", "reference_id": result.get("id")}

    # ── action helpers (parity with XSOAR) ───────────────────────────────

    async def isolate_host(self, host: str, tenant_id: str, attack_id: str) -> dict[str, Any]:
        return await self.fire(action="isolate_host", target=host,
                               tenant_id=tenant_id, attack_id=attack_id)

    async def kill_process(self, process: str, host: Optional[str], tenant_id: str, attack_id: str) -> dict[str, Any]:
        return await self.fire(
            action="kill_process", target=process,
            tenant_id=tenant_id, attack_id=attack_id,
            extra={"host": host} if host else None,
        )

    async def reset_credentials(self, user: str, tenant_id: str, attack_id: str) -> dict[str, Any]:
        return await self.fire(action="reset_credentials", target=user,
                               tenant_id=tenant_id, attack_id=attack_id)

    async def capture_forensic_snapshot(self, host: str, tenant_id: str, attack_id: str) -> dict[str, Any]:
        return await self.fire(action="capture_forensic_snapshot", target=host,
                               tenant_id=tenant_id, attack_id=attack_id)

    async def block_protocol(self, protocol: str, host: Optional[str], tenant_id: str, attack_id: str) -> dict[str, Any]:
        return await self.fire(
            action="block_protocol", target=protocol,
            tenant_id=tenant_id, attack_id=attack_id,
            extra={"host": host} if host else None,
        )

    async def review_auth_logs(self, host: str, tenant_id: str, attack_id: str) -> dict[str, Any]:
        return await self.fire(action="review_auth_logs", target=host,
                               tenant_id=tenant_id, attack_id=attack_id)


def _safe_host(url: str) -> str:
    try:
        from urllib.parse import urlparse
        return urlparse(url).hostname or ""
    except Exception:
        return ""
