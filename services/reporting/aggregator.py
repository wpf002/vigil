"""Metric computation for the reporting service.

Pulls aggregates from the other services via httpx and reduces them into
the executive-summary and trend payloads. None of the upstream calls are
mandatory — when a service is unreachable we substitute conservative
zero-defaults rather than failing the whole report.
"""

from __future__ import annotations
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from uuid import UUID

import httpx
import structlog

logger = structlog.get_logger(__name__)


def _zero_defaults() -> dict[str, Any]:
    return {
        "active_attacks": 0,
        "attacks_resolved_7d": 0,
        "mttr_seconds_7d": None,
        "sla_breach_rate_7d": None,
        "coverage_score": None,
        "top_tactic": None,
        "open_escalations": 0,
        "fp_rate_30d": None,
        "attacks_by_phase": {},
    }


class Aggregator:
    """Reads upstream services. Internally tolerates each call failing."""

    def __init__(
        self,
        *,
        attack_state_engine_url: str,
        detection_engine_url: str,
        analyst_portal_url: str,
        api_url: str,
        internal_api_key: Optional[str] = None,
        client_factory=None,
    ):
        self.attack_state_engine_url = attack_state_engine_url.rstrip("/")
        self.detection_engine_url = detection_engine_url.rstrip("/")
        self.analyst_portal_url = analyst_portal_url.rstrip("/")
        self.api_url = api_url.rstrip("/")
        self.internal_api_key = internal_api_key
        self._client_factory = client_factory or self._default_client_factory

    def _default_client_factory(self):
        return httpx.AsyncClient(timeout=10.0)

    def _headers(self, tenant_id: str, jwt: Optional[str]) -> dict[str, str]:
        h = {"Accept": "application/json"}
        if jwt:
            h["Authorization"] = f"Bearer {jwt}"
        else:
            h["X-Tenant-Id"] = str(tenant_id)
            if self.internal_api_key:
                h["X-Internal-Key"] = self.internal_api_key
        return h

    async def executive_summary(
        self, tenant_id: UUID, *, jwt: Optional[str] = None
    ) -> dict[str, Any]:
        out = _zero_defaults()
        async with self._client_factory() as client:
            await self._collect_attacks(client, str(tenant_id), jwt, out)
            await self._collect_coverage(client, str(tenant_id), jwt, out)
            await self._collect_escalations(client, str(tenant_id), jwt, out)
        out["computed_at"] = datetime.now(timezone.utc).isoformat()
        return out

    async def trend(
        self, tenant_id: UUID, *, days: int = 30, jwt: Optional[str] = None
    ) -> dict[str, Any]:
        out: dict[str, Any] = {
            "days": days,
            "attack_volume": [],
            "mttr_seconds": [],
            "sla_breach_rate": [],
        }
        async with self._client_factory() as client:
            try:
                resp = await client.get(
                    f"{self.attack_state_engine_url}/attacks/trend",
                    params={"days": days},
                    headers=self._headers(str(tenant_id), jwt),
                )
                if resp.status_code < 400:
                    body = resp.json()
                    inner = body.get("data") if isinstance(body, dict) and "data" in body else body
                    if isinstance(inner, dict):
                        out["attack_volume"] = inner.get("attack_volume") or []
                        out["mttr_seconds"] = inner.get("mttr_seconds") or []
                        out["sla_breach_rate"] = inner.get("sla_breach_rate") or []
            except Exception as e:
                logger.warning("reporting.trend.attack_state_unreachable", error=str(e))
        return out

    # ── upstream collectors ───────────────────────────────────────────────

    async def _collect_attacks(self, client, tenant_id: str, jwt: Optional[str], out: dict[str, Any]) -> None:
        try:
            resp = await client.get(
                f"{self.attack_state_engine_url}/attacks",
                params={"limit": 500},
                headers=self._headers(tenant_id, jwt),
            )
            if resp.status_code >= 400:
                return
            body = resp.json()
            attacks = body.get("data") if isinstance(body, dict) and "data" in body else body
            if not isinstance(attacks, list):
                return
            now = datetime.now(timezone.utc)
            since_7d = now - timedelta(days=7)
            active = 0
            resolved_7d = 0
            mttrs: list[float] = []
            phases: dict[str, int] = {}
            for a in attacks:
                phase = (a.get("current_phase") or a.get("phase") or "unknown").lower()
                phases[phase] = phases.get(phase, 0) + 1
                status = (a.get("status") or "").lower()
                if status not in {"resolved", "false_positive", "closed"}:
                    active += 1
                resolved_at = a.get("resolved_at") or a.get("closed_at")
                if resolved_at:
                    try:
                        dt = _parse_iso(resolved_at)
                        if dt and dt >= since_7d:
                            resolved_7d += 1
                            opened = _parse_iso(a.get("opened_at") or a.get("created_at"))
                            if opened:
                                mttrs.append((dt - opened).total_seconds())
                    except Exception:
                        continue
            out["active_attacks"] = active
            out["attacks_resolved_7d"] = resolved_7d
            out["attacks_by_phase"] = phases
            if mttrs:
                out["mttr_seconds_7d"] = round(sum(mttrs) / len(mttrs), 2)
            if phases:
                out["top_tactic"] = max(phases, key=phases.get)
        except Exception as e:
            logger.warning("reporting.attacks.unreachable", error=str(e))

    async def _collect_coverage(self, client, tenant_id: str, jwt: Optional[str], out: dict[str, Any]) -> None:
        try:
            resp = await client.get(
                f"{self.detection_engine_url}/coverage",
                headers=self._headers(tenant_id, jwt),
            )
            if resp.status_code >= 400:
                return
            body = resp.json()
            data = body.get("data") if isinstance(body, dict) and "data" in body else body
            if isinstance(data, dict):
                score = data.get("coverage_score")
                if score is None:
                    score = data.get("score")
                out["coverage_score"] = score
                # Average fp_rate across detections.
                detections = data.get("detections") or []
                if isinstance(detections, list):
                    rates = [
                        d.get("fp_rate")
                        for d in detections
                        if isinstance(d, dict) and isinstance(d.get("fp_rate"), (int, float))
                    ]
                    if rates:
                        out["fp_rate_30d"] = round(sum(rates) / len(rates), 4)
        except Exception as e:
            logger.warning("reporting.coverage.unreachable", error=str(e))

    async def _collect_escalations(self, client, tenant_id: str, jwt: Optional[str], out: dict[str, Any]) -> None:
        try:
            resp = await client.get(
                f"{self.analyst_portal_url}/queue",
                headers=self._headers(tenant_id, jwt),
            )
            if resp.status_code >= 400:
                return
            body = resp.json()
            queue = body.get("data") if isinstance(body, dict) and "data" in body else body
            if isinstance(queue, list):
                open_items = [q for q in queue if (q.get("status") or "").lower() != "resolved"]
                out["open_escalations"] = len(open_items)
                breaches = sum(1 for q in queue if q.get("sla_breached"))
                if queue:
                    out["sla_breach_rate_7d"] = round(breaches / len(queue), 4)
        except Exception as e:
            logger.warning("reporting.escalations.unreachable", error=str(e))


def _parse_iso(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        cleaned = value.rstrip("Z")
        if "." in cleaned:
            head, frac = cleaned.split(".", 1)
            cleaned = f"{head}.{frac[:6]}"
        cleaned = cleaned + "+00:00" if "+" not in cleaned and "-" not in cleaned[10:] else cleaned
        return datetime.fromisoformat(cleaned).astimezone(timezone.utc)
    except Exception:
        return None
