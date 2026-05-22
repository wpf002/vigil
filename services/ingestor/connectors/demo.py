"""Demo SIEM Connector.

Stand-in for a real SIEM connection. Emits a deterministic stream of
CDMEvents so the rest of the pipeline (correlation → attack-state → AI)
runs end-to-end without customer telemetry.

Each poll returns a small batch of events drawn from a curated playbook
covering the credential-access → lateral-movement → exfiltration chain.
The events advance the pipeline by referencing real detection_ids
(D1–D4) so the detection-engine's signal recorder fires on them.
"""

from __future__ import annotations

import itertools
import random
from datetime import datetime, timezone
from typing import Any, Iterator, Optional

import structlog

from ..models.cdm import (
    AlertStatus,
    CDMEvent,
    EventCategory,
    HostEntity,
    MITREMapping,
    NetworkEntity,
    ProcessEntity,
    Severity,
    UserEntity,
)

logger = structlog.get_logger(__name__)


# Each tuple: (detection_id, ATT&CK technique, severity, host, user, summary).
_PLAYBOOK: list[dict[str, Any]] = [
    {
        "detection_id": "D1-LSASS-MEMORY-ACCESS",
        "tactic": "credential-access",
        "tactic_id": "TA0006",
        "technique": "OS Credential Dumping",
        "technique_id": "T1003.001",
        "severity": Severity.HIGH,
        "title": "LSASS memory access from non-system process",
        "host": "WORKSTATION-12",
        "user": "jsmith",
        "process": "rundll32.exe",
    },
    {
        "detection_id": "D2-LSASS-DUMP-CREATION",
        "tactic": "credential-access",
        "tactic_id": "TA0006",
        "technique": "OS Credential Dumping",
        "technique_id": "T1003.001",
        "severity": Severity.HIGH,
        "title": "LSASS dump file written to disk",
        "host": "WORKSTATION-12",
        "user": "jsmith",
        "process": "procdump.exe",
    },
    {
        "detection_id": "D3-CREDENTIAL-REUSE-ANOMALY",
        "tactic": "credential-access",
        "tactic_id": "TA0006",
        "technique": "Valid Accounts",
        "technique_id": "T1078",
        "severity": Severity.MEDIUM,
        "title": "Service account login from unfamiliar host",
        "host": "DC-PRIMARY",
        "user": "svc_backup",
        "process": "lsass.exe",
    },
    {
        "detection_id": "D4-LATERAL-MOVEMENT-COMPROMISED-CREDS",
        "tactic": "lateral-movement",
        "tactic_id": "TA0008",
        "technique": "Remote Services: SMB/Windows Admin Shares",
        "technique_id": "T1021.002",
        "severity": Severity.HIGH,
        "title": "Lateral SMB connection using credentials from compromised host",
        "host": "FILESERVER-03",
        "user": "svc_backup",
        "process": "smbexec.exe",
    },
]


class DemoConnector:
    """Cycles through the curated playbook so each call to
    `get_events_since` yields the next batch in order."""

    def __init__(self, *, batch_size: int = 1):
        self.batch_size = batch_size
        self._cycle: Iterator[dict[str, Any]] = itertools.cycle(_PLAYBOOK)
        self._connected = False

    async def connect(self) -> None:
        self._connected = True
        logger.info("ingestor.demo.connected")

    async def disconnect(self) -> None:
        self._connected = False

    async def __aenter__(self):
        await self.connect()
        return self

    async def __aexit__(self, *args):
        await self.disconnect()

    async def health_check(self) -> bool:
        return self._connected

    async def get_events_since(
        self,
        *,
        since: Optional[datetime] = None,
        tenant_id: str,
    ) -> list[CDMEvent]:
        events: list[CDMEvent] = []
        for _ in range(self.batch_size):
            entry = next(self._cycle)
            ts = datetime.now(timezone.utc)
            ip_octet = random.randint(2, 254)
            ev = CDMEvent(
                tenant_id=tenant_id,
                source_event_id=f"demo-{int(ts.timestamp())}-{ip_octet}",
                source_siem="demo",
                timestamp=ts,
                category=EventCategory.AUTHENTICATION
                if entry["tactic"] == "credential-access"
                else EventCategory.NETWORK,
                severity=entry["severity"],
                status=AlertStatus.NEW,
                title=entry["title"],
                rule_name=entry["title"],
                rule_id=entry["detection_id"],
                detection_id=entry["detection_id"],
                user=UserEntity(username=entry["user"], domain="CORP"),
                host=HostEntity(
                    hostname=entry["host"],
                    ip=f"10.0.{ip_octet // 256 + 1}.{ip_octet % 256}",
                ),
                process=ProcessEntity(process_name=entry["process"]),
                network=NetworkEntity(
                    src_ip=f"10.0.10.{ip_octet}",
                    dst_ip=f"10.0.20.{ip_octet}",
                    protocol="tcp",
                ),
                mitre=MITREMapping(
                    tactic=entry["tactic"],
                    tactic_id=entry["tactic_id"],
                    technique=entry["technique"],
                    technique_id=entry["technique_id"],
                ),
                raw_event={"demo": True, "playbook_entry": entry["detection_id"]},
            )
            events.append(ev)
        return events
