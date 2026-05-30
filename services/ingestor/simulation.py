"""Agent-less attack simulation (purple-team).

A catalog of ATT&CK kill-chain scenarios. Running one synthesizes CDM events —
each carrying a detection_id + state_impact — and publishes them to the same
vigil.signals.raw topic the SIEM pollers feed, so a simulated attack flows
through correlation exactly like a real one and shows up in Active Threats.

No agent required: this is a server-side replay over the existing ingest
pipeline (the agent-less equivalent of running Caldera/Atomic in the
environment). Detections the scenario should trip are returned as the expected
set for a pass/fail purple-team check.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from uuid import UUID, uuid4

PLATFORM_TENANT = "00000000-0000-0000-0000-000000000000"

from .models.cdm import (
    CDMEvent,
    EventCategory,
    HostEntity,
    MITREMapping,
    Severity,
    UserEntity,
)

# Each step: (detection_id, rule_name, technique_id, tactic, status, confidence, progression)
_SCENARIOS: list[dict[str, Any]] = [
    {
        "id": "lsass-to-lateral",
        "name": "LSASS Credential Theft → Lateral Movement",
        "description": "Dump LSASS, reuse harvested credentials, then move laterally over SMB.",
        "severity": "critical",
        "steps": [
            ("D1-LSASS-MEMORY-ACCESS", "LSASS Memory Access", "T1003.001", "credential-access", "Observed", 0.25, False),
            ("D2-LSASS-DUMP-CREATION", "LSASS Dump Creation", "T1003.001", "credential-access", "Confirmed", 0.50, False),
            ("D3-CREDENTIAL-REUSE-ANOMALY", "Credential Reuse Anomaly", "T1078", "credential-access", "Observed", 0.20, False),
            ("D4-LATERAL-MOVEMENT-COMPROMISED-CREDS", "SMB Lateral Movement", "T1021.002", "lateral-movement", "Confirmed", 0.40, True),
        ],
    },
    {
        "id": "powershell-discovery",
        "name": "Encoded PowerShell → Domain Discovery",
        "description": "Encoded PowerShell execution followed by Active Directory account enumeration.",
        "severity": "high",
        "steps": [
            ("D5-POWERSHELL-ENCODED-COMMAND", "Encoded PowerShell Command", "T1059.001", "execution", "Confirmed", 0.40, False),
            ("D8-DOMAIN-ACCOUNT-DISCOVERY", "Domain Account Discovery", "T1087.002", "discovery", "Observed", 0.25, True),
        ],
    },
    {
        "id": "persist-c2-exfil",
        "name": "Persistence → C2 Beaconing → Exfiltration",
        "description": "New-service persistence, web-protocol C2 beaconing, exfil over an alternate protocol.",
        "severity": "critical",
        "steps": [
            ("D6-NEW-SERVICE-INSTALL", "New Service Installed", "T1543.003", "persistence", "Confirmed", 0.40, False),
            ("D9-WEB-PROTOCOL-BEACONING", "Web Protocol Beaconing", "T1071.001", "command-and-control", "Confirmed", 0.45, True),
            ("D10-EXFIL-ALTERNATIVE-PROTOCOL", "Exfiltration Over Alternative Protocol", "T1048", "exfiltration", "Confirmed", 0.50, True),
        ],
    },
]

_BY_ID = {s["id"]: s for s in _SCENARIOS}


def list_scenarios() -> list[dict[str, Any]]:
    return [
        {
            "id": s["id"],
            "name": s["name"],
            "description": s["description"],
            "severity": s["severity"],
            "steps": len(s["steps"]),
            "expected_detections": [step[0] for step in s["steps"]],
            "phases": sorted({step[3] for step in s["steps"]}),
        }
        for s in _SCENARIOS
    ]


def get_scenario(scenario_id: str) -> Optional[dict[str, Any]]:
    return _BY_ID.get(scenario_id)


def _severity(value: str) -> Severity:
    try:
        return Severity(value)
    except ValueError:
        return Severity.HIGH


async def coverage_report(pool, tenant_id: str, expected_detections: list[str]) -> dict[str, Any]:
    """Purple-team verdict: are the scenario's detections actually deployed for
    this tenant? Cross-references the expected detections against the tenant's
    active detection_versions (plus the platform/curated fallback) — a coverage
    gap means the simulated technique would go undetected.
    """
    active: set[str] = set()
    try:
        tid = UUID(tenant_id)
    except (ValueError, TypeError):
        tid = None
    if tid is not None and pool is not None:
        rows = await pool.fetch(
            "SELECT DISTINCT detection_id FROM detection_versions "
            "WHERE status='active' AND tenant_id = ANY($1::uuid[])",
            [tid, UUID(PLATFORM_TENANT)],
        )
        active = {r["detection_id"] for r in rows}
    results = [{"detection_id": d, "covered": d in active} for d in expected_detections]
    covered = sum(1 for r in results if r["covered"])
    total = len(expected_detections)
    return {
        "results": results,
        "covered": covered,
        "total": total,
        "coverage_pct": round(covered / total, 3) if total else 0.0,
        "verdict": "pass" if (total and covered == total) else ("partial" if covered else "fail"),
        "gaps": [r["detection_id"] for r in results if not r["covered"]],
    }


def build_events(
    scenario: dict[str, Any],
    tenant_id: str,
    *,
    host: str = "SIM-HOST-01",
    user: str = "sim_user",
    base_time: Optional[datetime] = None,
) -> list[CDMEvent]:
    now = base_time or datetime.now(timezone.utc)
    events: list[CDMEvent] = []
    for i, (det, rule, tech, tactic, status, conf, prog) in enumerate(scenario["steps"]):
        events.append(CDMEvent(
            tenant_id=tenant_id,
            source_event_id=f"sim-{scenario['id']}-{i}-{uuid4().hex[:8]}",
            source_siem="vigil_sim",
            timestamp=now + timedelta(seconds=i * 2),
            category=EventCategory.ENDPOINT,
            severity=_severity(scenario["severity"]),
            title=f"{rule} on {host}",
            description=f"[SIMULATION] {scenario['name']} — step {i + 1}: {tech} on {host}",
            rule_name=rule,
            detection_id=det,
            state_impact={
                "transitions_to": tactic,
                "status": status,
                "confidence_contribution": conf,
                "progression": prog,
            },
            host=HostEntity(hostname=host, ip="10.0.99.50"),
            user=UserEntity(username=user),
            mitre=MITREMapping(technique_id=tech, tactic=tactic),
            tags=["simulation", scenario["id"]],
            raw_event={"simulation": True, "scenario": scenario["id"], "step": i + 1},
        ))
    return events
