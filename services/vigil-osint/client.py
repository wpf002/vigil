"""Importable OSINT client for other VIGIL services.

Usage from any service (e.g. the narrative engine):

    from vigil_osint.client import osint_client
    observations = osint_client.enrich("8.8.8.8")

Talks to vigil-osint over HTTP. Mints a short-lived service JWT with the shared
VIGIL AUTH_SECRET so the call passes the same middleware a user request would.
Best-effort: returns [] on any failure so enrichment never breaks a caller.
"""

from __future__ import annotations

import os
import time
from typing import Any, Optional

import httpx
import jwt

JWT_ALGORITHM = "HS256"


class OsintClient:
    def __init__(
        self,
        base_url: Optional[str] = None,
        auth_secret: Optional[str] = None,
        timeout: float = 25.0,
    ) -> None:
        self.base_url = (base_url or os.getenv("OSINT_URL", "http://localhost:8012")).rstrip("/")
        self.auth_secret = auth_secret or os.getenv("AUTH_SECRET", "dev-only-secret-change-me")
        self.timeout = timeout

    def _service_token(self, tenant_id: str) -> str:
        now = int(time.time())
        payload = {
            "sub": "svc-osint-client",
            "tenant_id": tenant_id,
            "role": "service",
            "iat": now,
            "exp": now + 300,
        }
        return jwt.encode(payload, self.auth_secret, algorithm=JWT_ALGORITHM)

    def enrich(
        self,
        ioc_value: str,
        tenant_id: str = "system",
        connectors: Optional[list[str]] = None,
    ) -> list[dict[str, Any]]:
        """Enrich an IOC value, returning a list of Observation dicts.

        Synchronous and best-effort: returns [] rather than raising so a failed
        enrichment never breaks the calling narrative/detection flow.
        """
        token = self._service_token(tenant_id)
        body = {"query": ioc_value, "connectors": connectors or [], "filters": {}}
        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post(
                    f"{self.base_url}/osint/enrich",
                    json=body,
                    headers={"Authorization": f"Bearer {token}"},
                )
                resp.raise_for_status()
                return resp.json().get("observations", [])
        except Exception:  # noqa: BLE001 — enrichment is non-critical
            return []


osint_client = OsintClient()
