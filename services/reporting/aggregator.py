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
        """Build per-day series from raw attack data.

        attack-state-engine doesn't expose a trend endpoint, so we pull all
        attacks in the window and bucket them locally. Each chart-friendly
        series has a uniform `{date, count|value}` shape so the FE can render
        them with a single dataKey.
        """
        out: dict[str, Any] = {
            "days": days,
            "attack_volume": [],
            "mttr_seconds": [],
            "sla_breach_rate": [],
        }
        attacks: list[dict[str, Any]] = []
        async with self._client_factory() as client:
            try:
                resp = await client.get(
                    f"{self.attack_state_engine_url}/attacks",
                    # status=all so resolved/contained attacks are included —
                    # MTTR and SLA-breach series are computed from resolved
                    # attacks, which the default active-only view omits.
                    params={"limit": 200, "status": "all"},
                    headers=self._headers(str(tenant_id), jwt),
                )
                if resp.status_code < 400:
                    body = resp.json()
                    raw = body.get("data") if isinstance(body, dict) and "data" in body else body
                    if isinstance(raw, list):
                        attacks = raw
            except Exception as e:
                logger.warning("reporting.trend.attack_state_unreachable", error=str(e))

        # Build day buckets (UTC) for the trailing window.
        end = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        days_axis = [end - timedelta(days=i) for i in range(days - 1, -1, -1)]
        volume: dict[str, int] = {d.date().isoformat(): 0 for d in days_axis}
        mttrs_per_day: dict[str, list[float]] = {d.date().isoformat(): [] for d in days_axis}
        breaches_per_day: dict[str, list[float]] = {d.date().isoformat(): [] for d in days_axis}

        sla_seconds = 4 * 3600  # 4 hours from open → first response considered breach.

        now = datetime.now(timezone.utc)
        for a in attacks:
            opened = _parse_iso(a.get("opened_at") or a.get("first_seen") or a.get("created_at"))
            if opened is None:
                continue
            day_key = opened.astimezone(timezone.utc).date().isoformat()
            if day_key in volume:
                volume[day_key] += 1

            status = (a.get("status") or "").lower()
            resolved_raw = a.get("resolved_at") or a.get("closed_at")
            if not resolved_raw and status in {"resolved", "contained", "closed"}:
                resolved_raw = a.get("last_updated") or a.get("last_seen")
            resolved = _parse_iso(resolved_raw) if resolved_raw else None

            if resolved is not None and day_key in mttrs_per_day:
                mttrs_per_day[day_key].append((resolved - opened).total_seconds())

            # SLA breach for high-confidence attacks: scope to the open day.
            if (a.get("confidence") or 0) >= 0.7 and day_key in breaches_per_day:
                if resolved:
                    breach = (resolved - opened).total_seconds() > sla_seconds
                    breaches_per_day[day_key].append(1.0 if breach else 0.0)
                else:
                    age = (now - opened).total_seconds()
                    breaches_per_day[day_key].append(1.0 if age > sla_seconds else 0.0)

        out["attack_volume"] = [
            {"date": d.date().strftime("%m/%d"), "count": volume[d.date().isoformat()]}
            for d in days_axis
        ]
        out["mttr_seconds"] = [
            {
                "date": d.date().strftime("%m/%d"),
                "value": round(sum(mttrs_per_day[d.date().isoformat()]) / len(mttrs_per_day[d.date().isoformat()]), 2)
                if mttrs_per_day[d.date().isoformat()]
                else 0,
            }
            for d in days_axis
        ]
        out["sla_breach_rate"] = [
            {
                "date": d.date().strftime("%m/%d"),
                "value": round(
                    sum(breaches_per_day[d.date().isoformat()]) / len(breaches_per_day[d.date().isoformat()]),
                    4,
                )
                if breaches_per_day[d.date().isoformat()]
                else 0,
            }
            for d in days_axis
        ]
        return out

    # ── upstream collectors ───────────────────────────────────────────────

    async def _collect_attacks(self, client, tenant_id: str, jwt: Optional[str], out: dict[str, Any]) -> None:
        try:
            resp = await client.get(
                f"{self.attack_state_engine_url}/attacks",
                params={"limit": 200, "status": "all"},
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
            sla_breaches = 0
            sla_total = 0
            phases: dict[str, int] = {}
            for a in attacks:
                status = (a.get("status") or "").lower()
                # Phase distribution: only currently-active attacks.
                if status not in {"resolved", "false_positive", "closed", "contained"}:
                    phase = (a.get("current_phase") or a.get("phase") or "unknown").lower()
                    phases[phase] = phases.get(phase, 0) + 1
                    active += 1

                opened = _parse_iso(
                    a.get("opened_at") or a.get("created_at") or a.get("first_seen")
                )
                # Treat last_updated as the resolution timestamp once the
                # attack has reached a terminal status.
                resolved_at_raw = a.get("resolved_at") or a.get("closed_at")
                if not resolved_at_raw and status in {"resolved", "contained", "closed"}:
                    resolved_at_raw = a.get("last_updated") or a.get("last_seen")
                resolved_at = _parse_iso(resolved_at_raw) if resolved_at_raw else None

                if resolved_at and opened and resolved_at >= since_7d:
                    resolved_7d += 1
                    mttrs.append((resolved_at - opened).total_seconds())

                # SLA breach: high-confidence (≥0.7) attack either took
                # >4h to resolve or has been open >4h without resolution.
                if opened and (a.get("confidence") or 0) >= 0.7:
                    sla_total += 1
                    if resolved_at:
                        if (resolved_at - opened).total_seconds() > 4 * 3600:
                            sla_breaches += 1
                    elif (now - opened).total_seconds() > 4 * 3600:
                        sla_breaches += 1

            out["active_attacks"] = active
            out["attacks_resolved_7d"] = resolved_7d
            out["attacks_by_phase"] = phases
            if mttrs:
                out["mttr_seconds_7d"] = round(sum(mttrs) / len(mttrs), 2)
            if sla_total > 0:
                out["sla_breach_rate_7d"] = round(sla_breaches / sla_total, 4)
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
                # NOTE: sla_breach_rate_7d is owned solely by _collect_attacks
                # (high-confidence attacks past the 4h SLA). We deliberately do
                # NOT recompute it from the escalation queue's per-item
                # `sla_breached` flag here — doing so silently redefined the KPI
                # whenever the analyst-portal /queue was reachable.
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
