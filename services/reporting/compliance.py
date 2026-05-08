"""Compliance evidence assembly.

Each pack pulls aggregates from the existing services and shapes them to
match the criteria language an auditor expects. We never include raw event
data — only counts, lists of users + roles, and detection-version metadata.
"""

from __future__ import annotations
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from uuid import UUID

import httpx
import structlog

logger = structlog.get_logger(__name__)


class ComplianceAssembler:
    def __init__(
        self,
        *,
        api_url: str,
        attack_state_engine_url: str,
        detection_engine_url: str,
        analyst_portal_url: str,
        internal_api_key: Optional[str] = None,
        client_factory=None,
    ):
        self.api_url = api_url.rstrip("/")
        self.attack_state_engine_url = attack_state_engine_url.rstrip("/")
        self.detection_engine_url = detection_engine_url.rstrip("/")
        self.analyst_portal_url = analyst_portal_url.rstrip("/")
        self.internal_api_key = internal_api_key
        self._client_factory = client_factory or (lambda: httpx.AsyncClient(timeout=10.0))

    def _headers(self, tenant_id: str, jwt: Optional[str]) -> dict[str, str]:
        h = {"Accept": "application/json"}
        if jwt:
            h["Authorization"] = f"Bearer {jwt}"
        else:
            h["X-Tenant-Id"] = str(tenant_id)
            if self.internal_api_key:
                h["X-Internal-Key"] = self.internal_api_key
        return h

    # ── SOC 2 ─────────────────────────────────────────────────────────────

    async def soc2(
        self, tenant_id: UUID, *, period_days: int = 30, jwt: Optional[str] = None
    ) -> dict[str, Any]:
        period_start, period_end = _period_window(period_days)

        users: list[dict[str, Any]] = []
        attacks: list[dict[str, Any]] = []
        coverage: dict[str, Any] = {}
        detections_history: list[dict[str, Any]] = []

        async with self._client_factory() as client:
            users = await self._safe_list(
                client, f"{self.api_url}/auth/users", tenant_id=str(tenant_id), jwt=jwt
            )
            attacks = await self._safe_list(
                client, f"{self.attack_state_engine_url}/attacks",
                tenant_id=str(tenant_id), jwt=jwt,
            )
            coverage_body = await self._safe_get(
                client, f"{self.detection_engine_url}/coverage",
                tenant_id=str(tenant_id), jwt=jwt,
            )
            if isinstance(coverage_body, dict):
                coverage = coverage_body
            detections_history = await self._safe_list(
                client, f"{self.detection_engine_url}/detections",
                tenant_id=str(tenant_id), jwt=jwt,
            )

        return {
            "framework": "SOC 2 Type II",
            "tenant_id": str(tenant_id),
            "period_start": period_start.isoformat(),
            "period_end": period_end.isoformat(),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "criteria": [
                {
                    "criterion": "CC6 — Logical Access",
                    "evidence": [
                        {
                            "user_id": str(u.get("user_id") or u.get("id") or ""),
                            "email": u.get("email"),
                            "role": u.get("role"),
                            "last_login": u.get("last_login"),
                            "is_active": u.get("is_active", True),
                        }
                        for u in users
                    ],
                },
                {
                    "criterion": "CC7 — System Operations",
                    "evidence": {
                        "attack_state_counts": _count_by(attacks, "status"),
                        "detection_coverage_score": coverage.get("coverage_score") or coverage.get("score"),
                        "analyst_response_distribution": _bucket_response_times(attacks),
                    },
                },
                {
                    "criterion": "CC8 — Change Management",
                    "evidence": [
                        {
                            "detection_id": d.get("detection_id"),
                            "version": d.get("version"),
                            "deployed_at": d.get("deployed_at"),
                            "deployed_by": d.get("deployed_by"),
                            "status": d.get("status"),
                        }
                        for d in detections_history
                    ],
                },
            ],
        }

    # ── PCI-DSS ───────────────────────────────────────────────────────────

    async def pci(
        self, tenant_id: UUID, *, period_days: int = 30, jwt: Optional[str] = None
    ) -> dict[str, Any]:
        period_start, period_end = _period_window(period_days)
        transitions = 0
        coverage_score: Any = None
        last_deploy: Optional[str] = None

        async with self._client_factory() as client:
            transitions_body = await self._safe_get(
                client, f"{self.attack_state_engine_url}/transitions/count",
                tenant_id=str(tenant_id), jwt=jwt,
                params={"days": period_days},
            )
            if isinstance(transitions_body, dict):
                transitions = int(transitions_body.get("count") or 0)
            coverage_body = await self._safe_get(
                client, f"{self.detection_engine_url}/coverage",
                tenant_id=str(tenant_id), jwt=jwt,
            )
            if isinstance(coverage_body, dict):
                coverage_score = coverage_body.get("coverage_score") or coverage_body.get("score")
            detections = await self._safe_list(
                client, f"{self.detection_engine_url}/detections",
                tenant_id=str(tenant_id), jwt=jwt,
            )
            timestamps = [d.get("deployed_at") for d in detections if d.get("deployed_at")]
            if timestamps:
                last_deploy = max(timestamps)

        return {
            "framework": "PCI-DSS",
            "tenant_id": str(tenant_id),
            "period_start": period_start.isoformat(),
            "period_end": period_end.isoformat(),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "criteria": [
                {
                    "requirement": "Req 10 — Audit Logs",
                    "evidence": {
                        "attack_state_transitions": transitions,
                        "evidence_chain_complete": transitions > 0,
                    },
                },
                {
                    "requirement": "Req 11 — Security Testing",
                    "evidence": {
                        "detection_coverage_score": coverage_score,
                        "last_detection_deployment": last_deploy,
                    },
                },
            ],
        }

    # ── NIST CSF ──────────────────────────────────────────────────────────

    async def nist(
        self, tenant_id: UUID, *, period_days: int = 30, jwt: Optional[str] = None
    ) -> dict[str, Any]:
        period_start, period_end = _period_window(period_days)
        coverage: dict[str, Any] = {}
        detections: list[dict[str, Any]] = []
        attacks: list[dict[str, Any]] = []

        async with self._client_factory() as client:
            coverage = await self._safe_get(
                client, f"{self.detection_engine_url}/coverage",
                tenant_id=str(tenant_id), jwt=jwt,
            ) or {}
            detections = await self._safe_list(
                client, f"{self.detection_engine_url}/detections",
                tenant_id=str(tenant_id), jwt=jwt,
            )
            attacks = await self._safe_list(
                client, f"{self.attack_state_engine_url}/attacks",
                tenant_id=str(tenant_id), jwt=jwt,
            )

        fires = sum(int((d.get("performance") or {}).get("total_fires") or 0) for d in detections)
        fp_rates = [
            (d.get("performance") or {}).get("fp_rate")
            for d in detections
            if isinstance((d.get("performance") or {}).get("fp_rate"), (int, float))
        ]
        avg_fp = round(sum(fp_rates) / len(fp_rates), 4) if fp_rates else None
        mttr = _mean_mttr(attacks)
        resolved = sum(1 for a in attacks if (a.get("status") or "").lower() in {"resolved", "closed"})

        return {
            "framework": "NIST CSF",
            "tenant_id": str(tenant_id),
            "period_start": period_start.isoformat(),
            "period_end": period_end.isoformat(),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "functions": {
                "Identify": {
                    "coverage_by_tactic": coverage.get("by_tactic") or coverage.get("tactic_coverage") or {},
                },
                "Protect": {
                    "active_detections": len([d for d in detections if (d.get("status") or "active") == "active"]),
                },
                "Detect": {
                    "detection_fires_total": fires,
                    "avg_fp_rate": avg_fp,
                },
                "Respond": {
                    "mean_time_to_resolve_seconds": mttr,
                    "playbook_completion_rate": _playbook_completion_rate(attacks),
                },
                "Recover": {
                    "attacks_resolved": resolved,
                    "mean_recovery_time_seconds": mttr,
                },
            },
        }

    # ── audit log passthrough ────────────────────────────────────────────

    async def audit_log(
        self,
        tenant_id: UUID,
        *,
        days: int = 30,
        event_type: Optional[str] = None,
        user_id: Optional[UUID] = None,
        jwt: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        params: dict[str, Any] = {"days": days}
        if event_type:
            params["event_type"] = event_type
        if user_id:
            params["user_id"] = str(user_id)
        async with self._client_factory() as client:
            entries = await self._safe_list(
                client,
                f"{self.api_url}/auth/audit-log",
                tenant_id=str(tenant_id),
                jwt=jwt,
                params=params,
            )
        return entries

    # ── helpers ───────────────────────────────────────────────────────────

    async def _safe_get(
        self, client, url: str, *, tenant_id: str, jwt: Optional[str], params: Optional[dict] = None
    ) -> Optional[Any]:
        try:
            resp = await client.get(url, headers=self._headers(tenant_id, jwt), params=params or {})
            if resp.status_code >= 400:
                return None
            body = resp.json()
            return body.get("data") if isinstance(body, dict) and "data" in body else body
        except Exception as e:
            logger.warning("compliance.upstream_failed", url=url, error=str(e))
            return None

    async def _safe_list(
        self, client, url: str, *, tenant_id: str, jwt: Optional[str], params: Optional[dict] = None
    ) -> list[dict[str, Any]]:
        body = await self._safe_get(client, url, tenant_id=tenant_id, jwt=jwt, params=params)
        return body if isinstance(body, list) else []


def _period_window(days: int) -> tuple[datetime, datetime]:
    end = datetime.now(timezone.utc)
    return end - timedelta(days=days), end


def _count_by(items: list[dict[str, Any]], key: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for it in items:
        v = (it.get(key) or "unknown").lower()
        out[v] = out.get(v, 0) + 1
    return out


def _bucket_response_times(attacks: list[dict[str, Any]]) -> dict[str, int]:
    buckets = {"<1h": 0, "1-4h": 0, "4-24h": 0, ">24h": 0, "unknown": 0}
    for a in attacks:
        opened = _parse_iso(a.get("opened_at") or a.get("created_at"))
        responded = _parse_iso(a.get("first_response_at") or a.get("acknowledged_at"))
        if not (opened and responded):
            buckets["unknown"] += 1
            continue
        delta_h = (responded - opened).total_seconds() / 3600
        if delta_h < 1:
            buckets["<1h"] += 1
        elif delta_h < 4:
            buckets["1-4h"] += 1
        elif delta_h < 24:
            buckets["4-24h"] += 1
        else:
            buckets[">24h"] += 1
    return buckets


def _mean_mttr(attacks: list[dict[str, Any]]) -> Optional[float]:
    samples: list[float] = []
    for a in attacks:
        opened = _parse_iso(a.get("opened_at") or a.get("created_at"))
        resolved = _parse_iso(a.get("resolved_at") or a.get("closed_at"))
        if opened and resolved:
            samples.append((resolved - opened).total_seconds())
    if not samples:
        return None
    return round(sum(samples) / len(samples), 2)


def _playbook_completion_rate(attacks: list[dict[str, Any]]) -> Optional[float]:
    started = 0
    completed = 0
    for a in attacks:
        if a.get("playbook_started_at") or a.get("playbook_run_id"):
            started += 1
            if a.get("playbook_completed_at"):
                completed += 1
    if started == 0:
        return None
    return round(completed / started, 4)


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
