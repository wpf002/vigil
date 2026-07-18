"""
Event Normalizer

Maps raw Splunk events to VIGIL CDM.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Optional

import structlog

from ..models.cdm import (
    AlertStatus,
    CDMEvent,
    EventCategory,
    FileEntity,
    HostEntity,
    MITREMapping,
    NetworkEntity,
    ProcessEntity,
    Severity,
    SplunkCoreAlert,
    SplunkNotableEvent,
    UserEntity,
)

logger = structlog.get_logger(__name__)

SPLUNK_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL, "high": Severity.HIGH,
    "medium": Severity.MEDIUM, "low": Severity.LOW,
    "informational": Severity.INFO, "info": Severity.INFO,
    "1": Severity.INFO, "2": Severity.LOW, "3": Severity.MEDIUM,
    "4": Severity.HIGH, "5": Severity.CRITICAL,
}

SPLUNK_STATUS_MAP: dict[str, AlertStatus] = {
    "0": AlertStatus.NEW, "1": AlertStatus.IN_TRIAGE, "2": AlertStatus.IN_TRIAGE,
    "3": AlertStatus.RESOLVED, "4": AlertStatus.RESOLVED, "5": AlertStatus.CLOSED,
    "new": AlertStatus.NEW, "in progress": AlertStatus.IN_TRIAGE,
    "pending": AlertStatus.IN_TRIAGE, "resolved": AlertStatus.RESOLVED,
    "closed": AlertStatus.CLOSED,
}

MITRE_TACTIC_CATEGORY_MAP: dict[str, EventCategory] = {
    "initial-access": EventCategory.NETWORK, "execution": EventCategory.ENDPOINT,
    "persistence": EventCategory.ENDPOINT, "privilege-escalation": EventCategory.IDENTITY,
    "defense-evasion": EventCategory.ENDPOINT, "credential-access": EventCategory.IDENTITY,
    "discovery": EventCategory.NETWORK, "lateral-movement": EventCategory.NETWORK,
    "collection": EventCategory.ENDPOINT, "exfiltration": EventCategory.NETWORK,
    "command-and-control": EventCategory.NETWORK, "impact": EventCategory.ENDPOINT,
}

CATEGORY_KEYWORDS: dict[EventCategory, list[str]] = {
    EventCategory.AUTHENTICATION: ["login", "auth", "password", "credential", "kerberos", "ntlm", "saml", "mfa"],
    EventCategory.NETWORK: ["network", "firewall", "dns", "proxy", "traffic", "connection", "lateral"],
    EventCategory.ENDPOINT: ["process", "file", "registry", "service", "scheduled task", "wmi", "powershell"],
    EventCategory.CLOUD: ["aws", "azure", "gcp", "cloud", "s3", "blob", "iam"],
    EventCategory.EMAIL: ["email", "phish", "outlook", "exchange", "smtp"],
    EventCategory.DATABASE: ["sql", "database", "db", "query", "oracle", "mongo"],
    EventCategory.IDENTITY: ["user", "account", "privilege", "group", "admin", "permission"],
}


class EventNormalizer:

    def normalize_notable_event(self, event: SplunkNotableEvent, tenant_id: str) -> CDMEvent:
        return CDMEvent(
            tenant_id=tenant_id,
            source_event_id=event.event_id,
            source_siem="splunk_es",
            timestamp=self._parse_splunk_time(event._time),
            category=self._infer_category(event.rule_name, event.raw),
            severity=self._map_severity(event.severity or event.urgency),
            status=self._map_status(event.status),
            title=event.rule_name or "Unnamed Notable Event",
            description=event.raw.get("description"),
            rule_name=event.rule_name,
            rule_id=event.rule_id,
            user=self._extract_user(event.raw, event.user),
            host=self._extract_host_notable(event),
            network=self._extract_network(event.raw),
            process=self._extract_process(event.raw),
            file=self._extract_file(event.raw),
            mitre=self._extract_mitre(event.raw),
            risk_score=event.risk_score,
            urgency=event.urgency,
            raw_event=event.raw,
            tags=self._build_tags(event.raw),
        )

    def normalize_core_alert(self, alert: SplunkCoreAlert, tenant_id: str) -> list[CDMEvent]:
        events = []
        for i, result in enumerate(alert.results):
            events.append(CDMEvent(
                tenant_id=tenant_id,
                source_event_id=f"{alert.sid}_{i}",
                source_siem="splunk_core",
                timestamp=self._parse_splunk_time(result.get("_time")) or self._parse_splunk_time(alert.triggered_at),
                category=self._infer_category(alert.search_name, result),
                severity=self._map_severity(result.get("severity") or alert.severity),
                status=AlertStatus.NEW,
                title=alert.search_name,
                rule_name=alert.search_name,
                user=self._extract_user(result),
                host=self._extract_host_result(result),
                network=self._extract_network(result),
                process=self._extract_process(result),
                file=self._extract_file(result),
                mitre=self._extract_mitre(result),
                raw_event=result,
                tags=self._build_tags(result),
            ))
        return events

    def normalize_search_row(self, row: dict[str, Any], tenant_id: str) -> CDMEvent:
        """Normalize a raw Splunk search result row into a CDM event.

        Unlike notable/core-alert normalization, this carries NO detection_id —
        the row is a raw log line. The ingestor runs VIGIL's own detection
        evaluator over it to decide whether it's an attack signal.
        """
        # Splunk's | table returns multivalue fields as lists; flatten to a
        # single string so downstream (entity extraction, regex rules) is safe.
        row = {
            k: (next((x for x in v if x), None) if isinstance(v, list) else v)
            for k, v in row.items()
        }
        return CDMEvent(
            tenant_id=tenant_id,
            source_event_id=(
                row.get("_cd")
                or row.get("event_id")
                or f"{row.get('host','')}|{row.get('_time','')}|{row.get('process_name','')}"
            ),
            source_siem="splunk",
            timestamp=self._parse_splunk_time(row.get("_time")),
            category=EventCategory.UNKNOWN,
            severity=Severity.UNKNOWN,
            status=AlertStatus.NEW,
            title=row.get("process_name") or "splunk event",
            user=self._extract_user(row),
            host=self._extract_host_result(row),
            network=self._extract_network(row),
            process=self._extract_process(row),
            raw_event=row,
        )

    def _extract_user(self, raw: dict[str, Any], fallback: Optional[str] = None) -> Optional[UserEntity]:
        username = raw.get("user") or raw.get("src_user") or raw.get("dest_user") or fallback
        if not username:
            return None
        domain = None
        if "\\" in username:
            domain, username = username.split("\\", 1)
        elif "@" in username:
            username, domain = username.split("@", 1)
        return UserEntity(
            username=username, domain=domain,
            email=raw.get("email"),
            is_privileged=any(ind in username.lower() for ind in ["admin", "root", "sa", "svc_", "service", "system"]),
        )

    def _extract_host_notable(self, event: SplunkNotableEvent) -> Optional[HostEntity]:
        raw = event.raw
        hostname = raw.get("dest") or raw.get("host") or raw.get("dvc") or event.dest
        ip = raw.get("dest_ip") or raw.get("src_ip") or event.src
        if not hostname and not ip:
            return None
        return HostEntity(
            hostname=hostname if not self._is_ip(hostname) else None,
            ip=ip if self._is_ip(ip) else None,
            os=raw.get("os"),
        )

    def _extract_host_result(self, raw: dict[str, Any]) -> Optional[HostEntity]:
        hostname = raw.get("host") or raw.get("dest") or raw.get("dvc")
        ip = raw.get("src_ip") or raw.get("dest_ip") or raw.get("src") or raw.get("dest")
        if not hostname and not ip:
            return None
        return HostEntity(
            hostname=hostname if not self._is_ip(hostname) else None,
            ip=ip if self._is_ip(ip) else None,
            os=raw.get("os"),
        )

    def _extract_network(self, raw: dict[str, Any]) -> Optional[NetworkEntity]:
        src_ip = raw.get("src_ip") or raw.get("src")
        dst_ip = raw.get("dest_ip") or raw.get("dest")
        if not src_ip and not dst_ip:
            return None
        return NetworkEntity(
            src_ip=src_ip, dst_ip=dst_ip,
            src_port=self._to_int(raw.get("src_port")),
            dst_port=self._to_int(raw.get("dest_port") or raw.get("dst_port")),
            protocol=raw.get("protocol") or raw.get("transport"),
            bytes_in=self._to_int(raw.get("bytes_in")),
            bytes_out=self._to_int(raw.get("bytes_out")),
        )

    def _extract_process(self, raw: dict[str, Any]) -> Optional[ProcessEntity]:
        process_name = raw.get("process_name") or raw.get("process") or raw.get("Image")
        if not process_name:
            return None
        return ProcessEntity(
            process_name=process_name,
            process_id=self._to_int(raw.get("process_id") or raw.get("ProcessId")),
            parent_process_name=raw.get("parent_process_name") or raw.get("ParentImage"),
            parent_process_id=self._to_int(raw.get("parent_process_id")),
            command_line=raw.get("process") or raw.get("CommandLine") or raw.get("cmdline"),
            hash_md5=raw.get("MD5") or raw.get("file_hash"),
            hash_sha256=raw.get("SHA256"),
            path=raw.get("file_path") or raw.get("CurrentDirectory"),
        )

    def _extract_file(self, raw: dict[str, Any]) -> Optional[FileEntity]:
        file_name = raw.get("file_name") or raw.get("FileName") or raw.get("TargetFilename")
        if not file_name:
            return None
        return FileEntity(
            file_name=file_name,
            file_path=raw.get("file_path") or raw.get("TargetFilename"),
            file_hash=raw.get("file_hash") or raw.get("MD5"),
            file_size=self._to_int(raw.get("file_size")),
            action=raw.get("action") or raw.get("EventType"),
        )

    def _extract_mitre(self, raw: dict[str, Any]) -> Optional[MITREMapping]:
        tactic = raw.get("mitre_tactic") or raw.get("annotations.mitre_attack.mitre_tactic")
        technique = raw.get("mitre_technique") or raw.get("annotations.mitre_attack.mitre_technique")
        technique_id = raw.get("mitre_technique_id") or raw.get("annotations.mitre_attack.mitre_technique_id")
        if not tactic and not technique:
            return None
        return MITREMapping(
            tactic=tactic,
            tactic_id=raw.get("mitre_tactic_id"),
            technique=technique,
            technique_id=technique_id,
        )

    def _map_severity(self, raw: Optional[str]) -> Severity:
        if not raw:
            return Severity.UNKNOWN
        return SPLUNK_SEVERITY_MAP.get(raw.lower(), Severity.UNKNOWN)

    def _map_status(self, raw: Optional[str]) -> AlertStatus:
        if not raw:
            return AlertStatus.NEW
        return SPLUNK_STATUS_MAP.get(raw.lower(), AlertStatus.NEW)

    def _infer_category(self, rule_name: Optional[str], raw: dict[str, Any]) -> EventCategory:
        tactic = raw.get("mitre_tactic", "").lower().replace(" ", "-")
        if tactic in MITRE_TACTIC_CATEGORY_MAP:
            return MITRE_TACTIC_CATEGORY_MAP[tactic]
        if rule_name:
            name_lower = rule_name.lower()
            for category, keywords in CATEGORY_KEYWORDS.items():
                if any(kw in name_lower for kw in keywords):
                    return category
        return EventCategory.UNKNOWN

    def _build_tags(self, raw: dict[str, Any]) -> list[str]:
        tags = []
        if raw.get("mitre_technique_id"):
            tags.append(f"mitre:{raw['mitre_technique_id']}")
        if raw.get("mitre_tactic"):
            tags.append(f"tactic:{raw['mitre_tactic'].lower().replace(' ', '-')}")
        if raw.get("severity"):
            tags.append(f"severity:{raw['severity'].lower()}")
        return tags

    @staticmethod
    def _parse_splunk_time(time_str: Optional[str]) -> datetime:
        if not time_str:
            return datetime.now(timezone.utc)
        try:
            if time_str.replace(".", "").isdigit():
                return datetime.fromtimestamp(float(time_str), tz=timezone.utc)
            return datetime.fromisoformat(time_str.replace("Z", "+00:00"))
        except (ValueError, OSError):
            return datetime.now(timezone.utc)

    @staticmethod
    def _is_ip(value: Optional[str]) -> bool:
        if not value:
            return False
        return bool(re.match(r"^(\d{1,3}\.){3}\d{1,3}$", value))

    @staticmethod
    def _to_int(value: Any) -> Optional[int]:
        try:
            return int(value) if value is not None else None
        except (ValueError, TypeError):
            return None
