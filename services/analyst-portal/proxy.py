"""HTTP proxy to attack-state-engine.

Analysts work attack states owned by customer tenants; rather than duplicate
the schema, we proxy reads. Writes (status changes, comments) are recorded
in analyst_actions instead of mutating the customer-owned state.
"""

from __future__ import annotations

from typing import Any, Optional

import httpx
import structlog

from .config import AnalystPortalConfig

logger = structlog.get_logger(__name__)


class AttackStateProxy:
    def __init__(self, cfg: AnalystPortalConfig):
        self.base_url = cfg.attack_state_engine_url.rstrip("/")
        self.internal_key = cfg.internal_api_key

    async def get_attack(
        self,
        attack_id: str,
        tenant_id: str,
    ) -> Optional[dict[str, Any]]:
        url = f"{self.base_url}/attacks/{attack_id}"
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(
                    url,
                    headers={
                        "X-Tenant-Id": tenant_id,
                        "X-Internal-Key": self.internal_key,
                    },
                )
                if resp.status_code != 200:
                    return None
                body = resp.json()
                if isinstance(body, dict) and "data" in body:
                    return body["data"] if isinstance(body["data"], dict) else None
                return body if isinstance(body, dict) else None
        except Exception as e:
            logger.warning("analyst_portal.proxy.get_failed", attack_id=attack_id, error=str(e))
            return None
