"""Synchronous Python SDK for the VIGIL public API.

Authentication is via a Bearer API key (vgl_…). The client is thin: each
method maps to one HTTP call, unwraps the standard {data, meta, error}
envelope, and converts the payload into a dataclass.
"""

from __future__ import annotations
from typing import Any, Optional

import httpx

from .exceptions import (
    VIGILAPIError,
    VIGILAuthError,
    VIGILNotFoundError,
    VIGILRateLimitError,
)
from .models import AttackState, DetectionVersion, ExecutiveSummary, PlaybookRun


class VIGILClient:
    """Blocking HTTP client over the VIGIL public API.

    base_url should point at the API gateway (defaults to localhost:8000).
    Each service-specific URL can be overridden via the *_url constructor
    arguments — useful when running against a multi-host deployment.
    """

    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = "http://localhost:8000",
        attack_state_engine_url: Optional[str] = None,
        detection_engine_url: Optional[str] = None,
        ingestor_url: Optional[str] = None,
        reporting_url: Optional[str] = None,
        playbook_engine_url: Optional[str] = None,
        timeout: float = 30.0,
        client: Optional[httpx.Client] = None,
    ):
        if not api_key:
            raise ValueError("api_key is required")
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.attack_state_engine_url = (attack_state_engine_url or "http://localhost:8002").rstrip("/")
        self.detection_engine_url = (detection_engine_url or "http://localhost:8005").rstrip("/")
        self.ingestor_url = (ingestor_url or "http://localhost:8001").rstrip("/")
        self.reporting_url = (reporting_url or "http://localhost:8009").rstrip("/")
        self.playbook_engine_url = (playbook_engine_url or "http://localhost:8007").rstrip("/")
        self._owned_client = client is None
        self._client = client or httpx.Client(timeout=timeout)

    def close(self) -> None:
        if self._owned_client:
            self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    # ── shared HTTP plumbing ─────────────────────────────────────────────

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def _unwrap(self, body: Any) -> Any:
        if isinstance(body, dict) and "data" in body and "error" in body:
            if body.get("error"):
                raise VIGILAPIError(str(body["error"]))
            return body["data"]
        return body

    def _get(self, url: str, params: Optional[dict[str, Any]] = None) -> Any:
        return self._request("GET", url, params=params)

    def _post(self, url: str, json: Optional[dict[str, Any]] = None) -> Any:
        return self._request("POST", url, json=json)

    def _request(self, method: str, url: str, **kwargs) -> Any:
        try:
            resp = self._client.request(method, url, headers=self._headers(), **kwargs)
        except httpx.HTTPError as e:
            raise VIGILAPIError(f"network error: {e}") from e

        if resp.status_code in (401, 403):
            raise VIGILAuthError(f"auth failed: {resp.status_code}", status_code=resp.status_code)
        if resp.status_code == 404:
            raise VIGILNotFoundError("not found", status_code=404)
        if resp.status_code == 429:
            raise VIGILRateLimitError("rate limited", status_code=429)
        if resp.status_code >= 400:
            raise VIGILAPIError(
                f"api error {resp.status_code}: {resp.text[:200]}",
                status_code=resp.status_code,
                body=resp.text,
            )
        try:
            return self._unwrap(resp.json())
        except ValueError:
            return resp.text

    # ── public surface ───────────────────────────────────────────────────

    def list_attacks(
        self,
        *,
        phase: Optional[str] = None,
        min_confidence: Optional[float] = None,
        limit: int = 50,
    ) -> list[AttackState]:
        params: dict[str, Any] = {"limit": limit}
        if phase:
            params["phase"] = phase
        if min_confidence is not None:
            params["min_confidence"] = min_confidence
        body = self._get(f"{self.attack_state_engine_url}/attacks", params=params)
        if not isinstance(body, list):
            return []
        return [AttackState.from_dict(b) for b in body]

    def get_attack(self, attack_id: str) -> AttackState:
        body = self._get(f"{self.attack_state_engine_url}/attacks/{attack_id}")
        return AttackState.from_dict(body if isinstance(body, dict) else {})

    def list_detections(
        self, *, tactic: Optional[str] = None, limit: int = 100,
    ) -> list[DetectionVersion]:
        params: dict[str, Any] = {"limit": limit}
        if tactic:
            params["tactic"] = tactic
        body = self._get(f"{self.detection_engine_url}/detections", params=params)
        if not isinstance(body, list):
            return []
        return [DetectionVersion.from_dict(b) for b in body]

    def get_coverage(self) -> dict[str, Any]:
        body = self._get(f"{self.detection_engine_url}/coverage")
        return body if isinstance(body, dict) else {}

    def get_executive_summary(self) -> ExecutiveSummary:
        body = self._get(f"{self.reporting_url}/executive/summary")
        return ExecutiveSummary.from_dict(body if isinstance(body, dict) else {})

    def submit_signal(self, cdm_event: dict[str, Any]) -> dict[str, Any]:
        body = self._post(f"{self.ingestor_url}/signals", json=cdm_event)
        return body if isinstance(body, dict) else {}

    def list_playbooks(self, *, limit: int = 50) -> list[PlaybookRun]:
        body = self._get(
            f"{self.playbook_engine_url}/playbooks", params={"limit": limit}
        )
        if not isinstance(body, list):
            return []
        return [PlaybookRun.from_dict(b) for b in body]
