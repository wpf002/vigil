"""Fire-and-forget client for posting signal fires to the detection-engine.

Failures are intentionally swallowed: detection_signals is governance-grade
audit data, but losing a row must NOT block correlation. We log a warning
and move on.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional
from uuid import UUID

import httpx
import structlog

logger = structlog.get_logger(__name__)


class DetectionEngineClient:
    def __init__(
        self,
        base_url: str,
        internal_key: str,
        timeout_seconds: float = 5.0,
    ):
        self.base_url = (base_url or "").rstrip("/")
        self.internal_key = internal_key
        self.timeout = timeout_seconds
        self._client: Optional[httpx.AsyncClient] = None

    @property
    def enabled(self) -> bool:
        return bool(self.base_url)

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self.timeout)
        return self._client

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def record_signal(
        self,
        *,
        detection_id: str,
        tenant_id: str,
        fired_at: datetime,
        attack_id: Optional[UUID] = None,
        phase_contributed: Optional[str] = None,
        status_contributed: Optional[str] = None,
        confidence_contribution: Optional[float] = None,
    ) -> bool:
        """POST to /internal/signals/record. Returns True on success.

        Never raises — caller does not need to wrap in try/except.
        """
        if not self.enabled:
            return False
        try:
            client = await self._get_client()
            resp = await client.post(
                f"{self.base_url}/internal/signals/record",
                headers={"X-Internal-Key": self.internal_key},
                json={
                    "detection_id": detection_id,
                    "tenant_id": tenant_id,
                    "fired_at": fired_at.isoformat(),
                    "attack_id": str(attack_id) if attack_id is not None else None,
                    "phase_contributed": phase_contributed,
                    "status_contributed": status_contributed,
                    "confidence_contribution": confidence_contribution,
                },
            )
            if resp.status_code >= 400:
                logger.warning(
                    "detection_engine_client.record_failed",
                    status_code=resp.status_code,
                    detection_id=detection_id,
                )
                return False
            return True
        except Exception as e:
            logger.warning(
                "detection_engine_client.record_error",
                error=str(e),
                detection_id=detection_id,
            )
            return False
