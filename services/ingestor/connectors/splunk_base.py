"""
Splunk Base Connector

Async Splunk REST client. Handles auth, sessions,
search job lifecycle, and health checks.
"""

from __future__ import annotations
import asyncio
import ssl
from typing import Any, Optional
import httpx
import structlog
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential
from ..models.cdm import SplunkMode

logger = structlog.get_logger(__name__)


class SplunkAuthError(Exception):
    pass

class SplunkConnectionError(Exception):
    pass

class SplunkAPIError(Exception):
    pass


class SplunkBaseConnector:
    def __init__(
        self,
        host: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        token: Optional[str] = None,
        verify_ssl: bool = True,
        timeout: int = 30,
        mode: SplunkMode = SplunkMode.ES,
    ):
        if not token and not (username and password):
            raise ValueError("Provide either token or username+password")
        self.host = host.rstrip("/")
        self.username = username
        self.password = password
        self.token = token
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.mode = mode
        self._session_key: Optional[str] = None
        self._client: Optional[httpx.AsyncClient] = None

    async def connect(self) -> None:
        self._client = httpx.AsyncClient(
            verify=self.verify_ssl,
            timeout=self.timeout,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if self.token:
            self._client.headers.update({"Authorization": f"Bearer {self.token}"})
            logger.info("splunk.connected", mode="token", host=self.host)
        else:
            await self._authenticate()

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
        retry=retry_if_exception_type(SplunkConnectionError),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
    )
    async def _authenticate(self) -> None:
        try:
            resp = await self._client.post(
                f"{self.host}/services/auth/login",
                data={"username": self.username, "password": self.password, "output_mode": "json"},
            )
            resp.raise_for_status()
            self._session_key = resp.json()["sessionKey"]
            self._client.headers.update({"Authorization": f"Splunk {self._session_key}"})
            logger.info("splunk.authenticated", host=self.host, username=self.username)
        except httpx.ConnectError as e:
            raise SplunkConnectionError(f"Cannot reach Splunk at {self.host}: {e}") from e
        except httpx.HTTPStatusError as e:
            raise SplunkAuthError(f"Splunk auth failed: {e.response.status_code}") from e

    @retry(
        retry=retry_if_exception_type((SplunkConnectionError, httpx.TimeoutException)),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
    )
    async def run_search(
        self,
        spl: str,
        earliest: str = "-15m",
        latest: str = "now",
        max_count: int = 1000,
    ) -> list[dict[str, Any]]:
        if not self._client:
            raise SplunkConnectionError("Not connected.")
        try:
            resp = await self._client.post(
                f"{self.host}/services/search/jobs",
                data={
                    "search": f"search {spl}",
                    "earliest_time": earliest,
                    "latest_time": latest,
                    "output_mode": "json",
                    "exec_mode": "normal",
                },
            )
            resp.raise_for_status()
            sid = resp.json()["sid"]
        except httpx.HTTPStatusError as e:
            raise SplunkAPIError(f"Search job creation failed: {e}") from e

        await self._wait_for_job(sid)
        results = await self._fetch_results(sid, max_count)
        await self._delete_job(sid)
        return results

    async def _wait_for_job(self, sid: str, poll_interval: float = 0.5, max_wait: int = 60) -> None:
        elapsed = 0.0
        while elapsed < max_wait:
            resp = await self._client.get(
                f"{self.host}/services/search/jobs/{sid}",
                params={"output_mode": "json"},
            )
            resp.raise_for_status()
            state = resp.json()["entry"][0]["content"]
            dispatch_state = state.get("dispatchState", "")
            if dispatch_state in ("DONE", "FAILED", "FINALIZED"):
                if dispatch_state != "DONE":
                    raise SplunkAPIError(f"Search job {sid} ended in state: {dispatch_state}")
                return
            await asyncio.sleep(poll_interval)
            elapsed += poll_interval
            poll_interval = min(poll_interval * 1.5, 3.0)
        raise SplunkAPIError(f"Search job {sid} timed out after {max_wait}s")

    async def _fetch_results(self, sid: str, count: int = 1000) -> list[dict[str, Any]]:
        resp = await self._client.get(
            f"{self.host}/services/search/jobs/{sid}/results",
            params={"output_mode": "json", "count": count},
        )
        resp.raise_for_status()
        return resp.json().get("results", [])

    async def _delete_job(self, sid: str) -> None:
        try:
            await self._client.delete(f"{self.host}/services/search/jobs/{sid}")
        except Exception:
            pass

    async def get_server_info(self) -> dict[str, Any]:
        resp = await self._client.get(
            f"{self.host}/services/server/info",
            params={"output_mode": "json"},
        )
        resp.raise_for_status()
        return resp.json()["entry"][0]["content"]

    async def health_check(self) -> bool:
        try:
            info = await self.get_server_info()
            return bool(info.get("version"))
        except Exception as e:
            logger.warning("splunk.health_check.failed", error=str(e))
            return False
