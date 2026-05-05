"""
Splunk Core Connector

For orgs without Enterprise Security.
Polls triggered alerts and manages VIGIL-owned saved searches.
"""

from __future__ import annotations
from typing import Any, Optional
import structlog
from ..models.cdm import SplunkCoreAlert
from .splunk_base import SplunkBaseConnector

logger = structlog.get_logger(__name__)


class SplunkCoreConnector(SplunkBaseConnector):

    async def get_triggered_alerts(
        self,
        earliest: str = "-15m",
        latest: str = "now",
        max_alerts: int = 200,
    ) -> list[SplunkCoreAlert]:
        spl = (
            "| rest /services/alerts/fired_alerts "
            "| table title, savedsearch_name, trigger_time, severity, alert.severity, count, sid"
        )
        raw_results = await self.run_search(spl=spl, earliest=earliest, latest=latest, max_count=max_alerts)
        alerts = []
        for result in raw_results:
            try:
                sid = result.get("sid", "")
                if not sid:
                    continue
                alert_results = await self._fetch_alert_results(sid)
                alerts.append(SplunkCoreAlert(
                    sid=sid,
                    search_name=result.get("savedsearch_name", result.get("title", "")),
                    results=alert_results,
                    triggered_at=result.get("trigger_time"),
                    severity=result.get("severity") or result.get("alert.severity"),
                ))
            except Exception as e:
                logger.warning("splunk.core.parse_error", error=str(e))
        logger.info("splunk.core.polled", count=len(alerts))
        return alerts

    async def _fetch_alert_results(self, sid: str, max_results: int = 100) -> list[dict[str, Any]]:
        try:
            return await self._fetch_results(sid, count=max_results)
        except Exception as e:
            logger.warning("splunk.core.alert_results_failed", sid=sid, error=str(e))
            return []

    async def run_ad_hoc_search(
        self, spl: str, earliest: str = "-1h",
        latest: str = "now", max_results: int = 1000,
    ) -> list[dict[str, Any]]:
        """Run an arbitrary SPL search. Used by the AI engine for threat hunting."""
        return await self.run_search(spl=spl, earliest=earliest, latest=latest, max_count=max_results)

    async def create_saved_search(
        self, name: str, spl: str, cron: str,
        description: str = "", severity: str = "medium",
    ) -> bool:
        data = {
            "name": name, "search": spl, "cron_schedule": cron,
            "description": f"vigil_managed=true | {description}",
            "is_scheduled": "1", "alert_type": "number of events",
            "alert_comparator": "greater than", "alert_threshold": "0",
            "alert.severity": {"critical": "5", "high": "4", "medium": "3", "low": "2"}.get(severity, "3"),
            "alert.track": "1", "disabled": "0",
        }
        try:
            resp = await self._client.post(f"{self.host}/services/saved/searches", data=data)
            resp.raise_for_status()
            logger.info("splunk.core.saved_search.created", name=name)
            return True
        except Exception as e:
            logger.error("splunk.core.saved_search.create_failed", name=name, error=str(e))
            return False
