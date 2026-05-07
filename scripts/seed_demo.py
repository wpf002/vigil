"""
Seed realistic AttackStates by publishing CDMEvents to vigil.signals.raw.

Exercises the full pipeline (Kafka → correlation engine → Postgres → API).
Run from the repo root with the venv's python:

    .venv/bin/python scripts/seed_demo.py
"""

from __future__ import annotations
import json
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from kafka import KafkaProducer

ROOT = Path(__file__).resolve().parents[1]

# Hyphenated dirs aren't importable directly; load CDM via path injection.
import importlib.util


def _load(alias: str, dir_name: str):
    if alias in sys.modules:
        return sys.modules[alias]
    pkg = ROOT / "services" / dir_name
    spec = importlib.util.spec_from_file_location(
        alias, pkg / "__init__.py", submodule_search_locations=[str(pkg)]
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules[alias] = mod
    spec.loader.exec_module(mod)
    return mod


_load("ingestor", "ingestor")
from ingestor.models.cdm import (  # noqa: E402
    CDMEvent,
    EventCategory,
    HostEntity,
    MITREMapping,
    ProcessEntity,
    Severity,
    UserEntity,
)


import os

BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
TOPIC = os.getenv("KAFKA_TOPIC_SIGNALS", "vigil.signals.raw")
# Override with TENANT_ID=<uuid> when seeding for a registered user — the
# correlation engine writes AttackStates under whatever tenant_id the
# CDMEvent carries, and the API only returns rows matching the JWT tenant.
TENANT = os.getenv("TENANT_ID", "default")


def now_minus(minutes: float) -> datetime:
    return datetime.now(timezone.utc) - timedelta(minutes=minutes)


def cdm_event(
    *,
    detection_id: str,
    rule_name: str,
    minutes_ago: float,
    host: str | None = None,
    ip: str | None = None,
    user: str | None = None,
    process: str | None = None,
    parent_process: str | None = None,
    technique_id: str = "T1003.001",
    technique: str = "OS Credential Dumping",
    tactic: str = "credential-access",
    severity: Severity = Severity.HIGH,
    state_impact: dict | None = None,
) -> CDMEvent:
    return CDMEvent(
        tenant_id=TENANT,
        source_event_id=f"demo-{uuid4().hex[:10]}",
        source_siem="splunk_es",
        timestamp=now_minus(minutes_ago),
        category=EventCategory.ENDPOINT,
        severity=severity,
        title=rule_name,
        rule_name=rule_name,
        detection_id=detection_id,
        state_impact=state_impact,
        host=HostEntity(hostname=host, ip=ip) if (host or ip) else None,
        user=UserEntity(username=user) if user else None,
        process=ProcessEntity(process_name=process, parent_process_name=parent_process)
        if process
        else None,
        mitre=MITREMapping(
            tactic=tactic,
            technique=technique,
            technique_id=technique_id,
        ),
    )


# ── scenarios ────────────────────────────────────────────────────────────────
# Each list models a single AttackState narrative. Events arrive in chronological
# order; the correlation engine knits them together via shared entities.

SCENARIOS: list[dict] = [
    {
        "name": "Credential dumping → lateral movement on DC-PRIMARY",
        "events": [
            dict(
                detection_id="D1-LSASS-MEMORY-ACCESS",
                rule_name="LSASS Memory Access",
                minutes_ago=42,
                host="DC-PRIMARY",
                ip="10.0.1.5",
                user="svc_backup",
                process="rundll32.exe",
                parent_process="powershell.exe",
            ),
            dict(
                detection_id="D2-LSASS-DUMP-CREATION",
                rule_name="LSASS Dump File Creation",
                minutes_ago=38,
                host="DC-PRIMARY",
                user="svc_backup",
                process="comsvcs.dll",
                severity=Severity.CRITICAL,
            ),
            dict(
                detection_id="D4-LATERAL-MOVEMENT-COMPROMISED-CREDS",
                rule_name="Lateral Movement w/ Compromised Credentials",
                minutes_ago=12,
                host="DC-PRIMARY",
                user="svc_backup",
                tactic="lateral-movement",
                technique_id="T1021.002",
                technique="SMB/Windows Admin Shares",
            ),
        ],
    },
    {
        "name": "LSASS dumping observed on LAPTOP-FINANCE-04",
        "events": [
            dict(
                detection_id="D1-LSASS-MEMORY-ACCESS",
                rule_name="LSASS Memory Access",
                minutes_ago=18,
                host="LAPTOP-FINANCE-04",
                ip="10.0.20.41",
                user="kchen",
                process="procdump.exe",
            ),
            dict(
                detection_id="D2-LSASS-DUMP-CREATION",
                rule_name="LSASS Dump File Creation",
                minutes_ago=14,
                host="LAPTOP-FINANCE-04",
                user="kchen",
                process="procdump.exe",
                severity=Severity.CRITICAL,
            ),
        ],
    },
    {
        "name": "Suspicious credential reuse — jsmith",
        "events": [
            dict(
                detection_id="D3-CREDENTIAL-REUSE-ANOMALY",
                rule_name="Credential Reuse Anomaly",
                minutes_ago=22,
                host="WORKSTATION-12",
                user="jsmith",
                technique_id="T1078.002",
                technique="Domain Accounts",
            ),
            dict(
                detection_id="D3-CREDENTIAL-REUSE-ANOMALY",
                rule_name="Credential Reuse Anomaly",
                minutes_ago=8,
                host="WORKSTATION-19",
                user="jsmith",
                technique_id="T1078.002",
                technique="Domain Accounts",
            ),
        ],
    },
    {
        "name": "LSASS access (single signal) — DEV-BUILD-07",
        "events": [
            dict(
                detection_id="D1-LSASS-MEMORY-ACCESS",
                rule_name="LSASS Memory Access",
                minutes_ago=4,
                host="DEV-BUILD-07",
                ip="10.0.50.12",
                user="ci-runner",
                process="taskmgr.exe",
            ),
        ],
    },
    {
        "name": "Stale C2 staging on SERVER-DB-01 (decreasing)",
        "events": [
            dict(
                detection_id="SYNTH-C2-BEACON",
                rule_name="C2 Beacon Heuristic",
                minutes_ago=240,
                host="SERVER-DB-01",
                ip="10.0.30.11",
                user="SYSTEM",
                process="svchost.exe",
                tactic="command-and-control",
                technique_id="T1071.001",
                technique="Web Protocols",
                severity=Severity.HIGH,
                state_impact={
                    "transitions_to": "command-and-control",
                    "status": "Confirmed",
                    "confidence_contribution": 0.6,
                },
            ),
            dict(
                detection_id="SYNTH-C2-BEACON",
                rule_name="C2 Beacon Heuristic",
                minutes_ago=180,
                host="SERVER-DB-01",
                ip="10.0.30.11",
                user="SYSTEM",
                process="svchost.exe",
                tactic="command-and-control",
                technique_id="T1071.001",
                technique="Web Protocols",
                severity=Severity.HIGH,
                state_impact={
                    "transitions_to": "command-and-control",
                    "status": "Observed",
                    "confidence_contribution": 0.3,
                },
            ),
        ],
    },
    {
        "name": "Exfil staging on FILESERVER-03",
        "events": [
            dict(
                detection_id="SYNTH-EXFIL-STAGING",
                rule_name="Large Archive Created Outside Backup Window",
                minutes_ago=15,
                host="FILESERVER-03",
                ip="10.0.40.8",
                user="contractor_acme",
                process="7z.exe",
                tactic="collection",
                technique_id="T1560.001",
                technique="Archive via Utility",
                severity=Severity.HIGH,
                state_impact={
                    "transitions_to": "collection",
                    "status": "Observed",
                    "confidence_contribution": 0.4,
                },
            ),
            dict(
                detection_id="SYNTH-EXFIL-NETWORK",
                rule_name="Outbound Transfer to Unknown Cloud Storage",
                minutes_ago=6,
                host="FILESERVER-03",
                ip="10.0.40.8",
                user="contractor_acme",
                process="curl.exe",
                tactic="exfiltration",
                technique_id="T1567.002",
                technique="Exfiltration to Cloud Storage",
                severity=Severity.CRITICAL,
                state_impact={
                    "transitions_to": "exfiltration",
                    "status": "Confirmed",
                    "confidence_contribution": 0.7,
                    "progression": True,
                },
            ),
        ],
    },
]


def main() -> None:
    producer = KafkaProducer(
        bootstrap_servers=BOOTSTRAP,
        value_serializer=lambda v: json.dumps(v, default=str).encode("utf-8"),
        key_serializer=lambda k: k.encode("utf-8") if k else None,
        acks="all",
        retries=3,
    )
    print(f"Connected to Kafka at {BOOTSTRAP}, publishing to {TOPIC}\n")

    total = 0
    for scenario in SCENARIOS:
        print(f"→ {scenario['name']}")
        for kw in scenario["events"]:
            event = cdm_event(**kw)
            producer.send(
                TOPIC,
                key=event.tenant_id,
                value=event.model_dump(mode="json"),
            ).get(timeout=10)
            total += 1
            print(f"   • {kw['detection_id']:35s} {kw.get('host') or kw.get('user'):24s} {kw['minutes_ago']:>5.1f}m ago")
            time.sleep(0.05)
        print()

    producer.flush()
    producer.close(timeout=5)
    print(f"published {total} events. Waiting 3s for the AI engine to generate narratives…")
    # Give the AI engine a head start so the analyst sees populated narratives
    # the first time they refresh — the consumer pipeline is async so without
    # this pause the UI flickers between "Generating…" and the final text.
    time.sleep(3)
    print("done. Watch the correlation engine logs and refresh the UI.")


if __name__ == "__main__":
    main()
