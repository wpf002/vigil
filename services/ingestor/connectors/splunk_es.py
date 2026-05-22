"""
Splunk Enterprise Security Connector

Polls ES Notable Events, manages correlation searches,
and writes risk scores back to the Risk Index.
"""

from __future__ import annotations

from typing import Any, Optional

import structlog

from ..models.cdm import SplunkNotableEvent
from .splunk_base import SplunkAPIError, SplunkBaseConnector

logger = structlog.get_logger(__name__)

NOTABLE_FIELDS = [
    "event_id", "source", "rule_name", "rule_id", "rule_title",
    "severity", "urgency", "status", "owner", "src", "dest", "user",
    "src_user", "dest_user", "risk_score", "mitre_technique",
    "mitre_technique_id", "mitre_tactic", "mitre_tactic_id", "_time",
    "search_name", "info_search_name", "orig_source", "orig_sourcetype",
    "annotations.mitre_attack.mitre_technique_id",
    "annotations.mitre_attack.mitre_tactic",
]


class SplunkESConnector(SplunkBaseConnector):
    ES_NOTABLE_INDEX = "notable"
    ES_RISK_INDEX = "risk"

    async def get_notable_events(
        self,
        earliest: str = "-15m",
        latest: str = "now",
        status_filter: Optional[list[str]] = None,
        severity_filter: Optional[list[str]] = None,
        max_events: int = 500,
    ) -> list[SplunkNotableEvent]:
        filters = self._build_notable_filters(status_filter, severity_filter)
        spl = self._build_notable_spl(filters)
        logger.info("splunk.es.polling_notables", earliest=earliest, latest=latest)
        raw_results = await self.run_search(spl=spl, earliest=earliest, latest=latest, max_count=max_events)
        events = []
        for result in raw_results:
            try:
                events.append(self._parse_notable_event(result))
            except Exception as e:
                logger.warning("splunk.es.parse_error", error=str(e))
        logger.info("splunk.es.polled", count=len(events))
        return events

    def _build_notable_filters(self, status_filter, severity_filter):
        filters = []
        if status_filter:
            filters.append("(" + " OR ".join(f'status="{s}"' for s in status_filter) + ")")
        if severity_filter:
            filters.append("(" + " OR ".join(f'severity="{s}"' for s in severity_filter) + ")")
        return filters

    def _build_notable_spl(self, filters):
        base = f"index={self.ES_NOTABLE_INDEX}"
        filter_str = " ".join(filters)
        field_list = " ".join(NOTABLE_FIELDS)
        return f"{base} {filter_str} | table {field_list}".strip()

    def _parse_notable_event(self, raw: dict[str, Any]) -> SplunkNotableEvent:
        return SplunkNotableEvent(
            event_id=raw.get("event_id", raw.get("_cd", "")),
            source=raw.get("source") or raw.get("orig_source"),
            rule_name=raw.get("rule_name") or raw.get("rule_title") or raw.get("search_name"),
            rule_id=raw.get("rule_id"),
            severity=raw.get("severity"),
            urgency=raw.get("urgency"),
            status=raw.get("status"),
            owner=raw.get("owner"),
            src=raw.get("src"),
            dest=raw.get("dest"),
            user=raw.get("user") or raw.get("src_user"),
            risk_score=self._parse_float(raw.get("risk_score")),
            mitre_technique=raw.get("mitre_technique"),
            _time=raw.get("_time"),
            search_name=raw.get("search_name") or raw.get("info_search_name"),
            raw=raw,
        )

    async def get_correlation_searches(self) -> list[dict[str, Any]]:
        spl = (
            "| rest /services/saved/searches "
            "| search action.correlationsearch.enabled=1 "
            "| table title, description, search, cron_schedule, disabled"
        )
        return await self.run_search(spl=spl, earliest="-1m", latest="now")

    async def create_correlation_search(
        self, name: str, spl: str, cron: str,
        description: str = "", severity: str = "medium",
    ) -> bool:
        data = {
            "name": name, "search": spl, "cron_schedule": cron,
            "description": description,
            "action.correlationsearch.enabled": "1",
            "action.correlationsearch.label": name,
            "alert.severity": self._severity_to_int(severity),
            "is_scheduled": "1", "disabled": "0",
        }
        try:
            resp = await self._client.post(f"{self.host}/services/saved/searches", data=data)
            resp.raise_for_status()
            logger.info("splunk.es.correlation_search.created", name=name)
            return True
        except Exception as e:
            logger.error("splunk.es.correlation_search.create_failed", name=name, error=str(e))
            return False

    async def write_risk_score(
        self, object_name: str, object_type: str,
        risk_score: float, rule_name: str, source: str = "vigil",
    ) -> bool:
        spl = (
            f'| makeresults '
            f'| eval risk_object="{object_name}", risk_object_type="{object_type}", '
            f'risk_score={risk_score}, rule_name="{rule_name}", source="{source}" '
            f'| collect index={self.ES_RISK_INDEX}'
        )
        try:
            await self.run_search(spl=spl, earliest="-1m", latest="now")
            return True
        except SplunkAPIError as e:
            logger.error("splunk.es.risk_score.write_failed", error=str(e))
            return False

    async def update_notable_status(
        self, event_id: str, status: str,
        owner: Optional[str] = None, comment: Optional[str] = None,
    ) -> bool:
        data: dict[str, Any] = {"ruleUIDs": [event_id], "status": status}
        if owner:
            data["newOwner"] = owner
        if comment:
            data["comment"] = comment
        try:
            resp = await self._client.post(f"{self.host}/services/notable_update", data=data)
            resp.raise_for_status()
            return True
        except Exception as e:
            logger.error("splunk.es.notable.update_failed", event_id=event_id, error=str(e))
            return False

    @staticmethod
    def _parse_float(value):
        try:
            return float(value) if value is not None else None
        except (ValueError, TypeError):
            return None

    @staticmethod
    def _severity_to_int(severity: str) -> str:
        return {"critical": "5", "high": "4", "medium": "3", "low": "2", "info": "1"}.get(severity.lower(), "3")
