"""One-off: seed a rich, realistic demo dataset for a single tenant directly
into the Railway Postgres.

Builds schema-valid AttackState rows (via the real attack-state-engine model),
attack_state_transitions, playbook_runs, and one working API key — all scoped
to TENANT_ID. The reporting/attack-state APIs read straight from these tables,
so every dashboard, the Active Threats board, Playbooks and Settings fill in.

Run:  services/api/.venv/bin/python scripts/seed_railway_demo.py
Env:  DATABASE_URL, TENANT_ID, CREATED_BY (user_id)
"""

from __future__ import annotations

import asyncio
import hashlib
import importlib.util
import json
import os
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID, uuid4

import asyncpg
import bcrypt

ROOT = Path(__file__).resolve().parents[1]
RANDOM_SEED = 42
random.seed(RANDOM_SEED)

DATABASE_URL = os.environ["DATABASE_URL"]
TENANT_ID = os.environ["TENANT_ID"]
CREATED_BY = UUID(os.environ["CREATED_BY"])

# ── load the real AttackState model (hyphenated dir → importlib) ──────────────
_spec = importlib.util.spec_from_file_location(
    "vigil_attack_state_model",
    ROOT / "services" / "attack-state-engine" / "models" / "attack_state.py",
)
m = importlib.util.module_from_spec(_spec)
sys.modules["vigil_attack_state_model"] = m
_spec.loader.exec_module(m)

AttackState = m.AttackState
EvidenceItem = m.EvidenceItem
PhaseState = m.PhaseState
ResponseAction = m.ResponseAction
ResponseStatus = m.ResponseStatus
MITRETactic = m.MITRETactic
ImpactLevel = m.ImpactLevel
Momentum = m.Momentum
PhaseStatus = m.PhaseStatus
AttackStateStatus = m.AttackStateStatus

NOW = datetime.now(timezone.utc)

# ── kill-chain scenario templates ─────────────────────────────────────────────
# Each step: (tactic, technique_id, technique_name, detection_id, rule_name)
T = MITRETactic
SCENARIOS = [
    ("Ransomware", "Critical", [
        (T.INITIAL_ACCESS, "T1566.001", "Spearphishing Attachment", "D7-PHISH-ATTACHMENT", "Malicious Office Macro"),
        (T.EXECUTION, "T1059.001", "PowerShell", "D5-PS-ENCODED-CMD", "Encoded PowerShell Command"),
        (T.PERSISTENCE, "T1547.001", "Registry Run Keys", "D9-RUNKEY-PERSIST", "Run Key Persistence"),
        (T.PRIVILEGE_ESCALATION, "T1068", "Exploitation for Priv Esc", "D11-PRIVESC-EXPLOIT", "Kernel Exploit Attempt"),
        (T.DEFENSE_EVASION, "T1562.001", "Disable Security Tools", "D8-AV-TAMPER", "Defender Tamper"),
        (T.CREDENTIAL_ACCESS, "T1003.001", "LSASS Memory", "D1-LSASS-MEMORY-ACCESS", "LSASS Memory Access"),
        (T.LATERAL_MOVEMENT, "T1021.002", "SMB/Windows Admin Shares", "D2-SMB-LATERAL", "SMB Lateral Movement"),
        (T.IMPACT, "T1486", "Data Encrypted for Impact", "D12-RANSOM-ENCRYPT", "Mass File Encryption"),
    ]),
    ("Credential Access", "High", [
        (T.CREDENTIAL_ACCESS, "T1003.001", "OS Credential Dumping", "D1-LSASS-MEMORY-ACCESS", "LSASS Memory Access"),
        (T.LATERAL_MOVEMENT, "T1021.002", "SMB/Windows Admin Shares", "D2-SMB-LATERAL", "SMB Lateral Movement"),
        (T.DISCOVERY, "T1087.002", "Domain Account Discovery", "D6-AD-RECON", "AD Account Enumeration"),
    ]),
    ("Data Exfiltration", "Critical", [
        (T.INITIAL_ACCESS, "T1190", "Exploit Public-Facing App", "D10-WEB-EXPLOIT", "Web App Exploitation"),
        (T.COLLECTION, "T1005", "Data from Local System", "D13-BULK-COLLECT", "Bulk Data Staging"),
        (T.COMMAND_AND_CONTROL, "T1071.001", "Web Protocols", "D4-C2-BEACON", "C2 Beacon Detected"),
        (T.EXFILTRATION, "T1041", "Exfil Over C2 Channel", "D14-EXFIL-C2", "Exfiltration Over C2"),
    ]),
    ("Cloud Account Compromise", "High", [
        (T.INITIAL_ACCESS, "T1078.004", "Cloud Accounts", "D15-CLOUD-IMPOSSIBLE-TRAVEL", "Impossible Travel"),
        (T.PERSISTENCE, "T1098.001", "Additional Cloud Credentials", "D16-CLOUD-KEY-CREATE", "New Access Key Created"),
        (T.PRIVILEGE_ESCALATION, "T1484.002", "Trust Modification", "D17-CLOUD-ROLE-ESCALATE", "IAM Role Escalation"),
        (T.EXFILTRATION, "T1530", "Data from Cloud Storage", "D18-CLOUD-S3-EXFIL", "S3 Bulk Download"),
    ]),
    ("Phishing to C2", "Medium", [
        (T.INITIAL_ACCESS, "T1566.002", "Spearphishing Link", "D7-PHISH-LINK", "Credential Phishing Link"),
        (T.EXECUTION, "T1204.002", "Malicious File", "D5-USER-EXEC", "User Executed Dropper"),
        (T.COMMAND_AND_CONTROL, "T1071.004", "DNS", "D4-DNS-TUNNEL", "DNS Tunneling"),
    ]),
    ("Web Server Compromise", "High", [
        (T.INITIAL_ACCESS, "T1190", "Exploit Public-Facing App", "D10-WEB-EXPLOIT", "Web App Exploitation"),
        (T.EXECUTION, "T1059.004", "Unix Shell", "D19-WEBSHELL-EXEC", "Web Shell Command"),
        (T.PERSISTENCE, "T1505.003", "Web Shell", "D20-WEBSHELL-DROP", "Web Shell Dropped"),
        (T.DISCOVERY, "T1046", "Network Service Scanning", "D21-NET-SCAN", "Internal Port Scan"),
    ]),
    ("Privilege Escalation", "Medium", [
        (T.EXECUTION, "T1059.003", "Windows Command Shell", "D22-CMD-SPAWN", "Suspicious cmd.exe Spawn"),
        (T.PRIVILEGE_ESCALATION, "T1548.002", "Bypass UAC", "D23-UAC-BYPASS", "UAC Bypass Attempt"),
        (T.DEFENSE_EVASION, "T1070.004", "File Deletion", "D24-LOG-CLEAR", "Event Log Cleared"),
    ]),
    ("Insider Data Theft", "High", [
        (T.DISCOVERY, "T1018", "Remote System Discovery", "D21-NET-SCAN", "Internal Host Discovery"),
        (T.COLLECTION, "T1213", "Data from Repositories", "D25-REPO-MASS-PULL", "Mass Repository Clone"),
        (T.EXFILTRATION, "T1567.002", "Exfil to Cloud Storage", "D26-EXFIL-CLOUD", "Upload to Personal Cloud"),
    ]),
]

HOSTS = [
    "DC-PRIMARY", "DC-SECONDARY", "WORKSTATION-12", "WORKSTATION-19", "LAPTOP-FINANCE-04",
    "LAPTOP-HR-08", "SRV-FILE-01", "SRV-WEB-03", "SRV-SQL-02", "SRV-BACKUP-01",
    "VPN-GATEWAY", "JUMPBOX-01", "K8S-NODE-04", "BUILD-AGENT-02", "EXEC-LAPTOP-CEO",
]
IPS = ["10.0.1.5", "10.0.1.6", "10.0.20.41", "10.0.20.88", "10.0.5.12", "10.0.5.30",
       "10.0.8.4", "10.0.8.9", "172.16.4.10", "172.16.4.22", "192.168.50.7"]
USERS = ["svc_backup", "jsmith", "kchen", "mpatel", "awilliams", "admin_ops",
         "svc_sql", "dlee", "rgupta", "tnguyen", "svc_jenkins"]
SIEMS = ["splunk_es", "sentinel", "elastic", "splunk_core"]


def _pick_phase_status(idx: int, total: int, terminal: bool) -> "PhaseStatus":
    # earlier phases confirmed, the leading edge observed (unless terminal)
    if idx < total - 1:
        return PhaseStatus.CONFIRMED
    return PhaseStatus.CONFIRMED if terminal else random.choice(
        [PhaseStatus.OBSERVED, PhaseStatus.CONFIRMED]
    )


def build_attack(scenario, *, opened: datetime, n_steps: int, status, confidence: float,
                 momentum, resolved_after: timedelta | None) -> "AttackState":
    label, impact, steps = scenario
    steps = steps[:n_steps]
    terminal = status in (AttackStateStatus.RESOLVED, AttackStateStatus.CONTAINED)
    host = random.choice(HOSTS)
    ip = random.choice(IPS)
    user = random.choice(USERS)
    siem = random.choice(SIEMS)

    # spread step timestamps between opened and (resolved or now)
    end = opened + resolved_after if resolved_after else min(NOW, opened + timedelta(hours=random.uniform(1, 20)))
    span = max((end - opened).total_seconds(), 60)
    phases: list = []
    evidence: list = []
    for i, (tactic, tech_id, tech_name, det_id, rule) in enumerate(steps):
        ts = opened + timedelta(seconds=span * (i / max(len(steps) - 1, 1)))
        pstatus = _pick_phase_status(i, len(steps), terminal)
        ev_id = uuid4()
        evidence.append(EvidenceItem(
            evidence_id=ev_id,
            signal_id=str(uuid4()),
            detection_id=det_id,
            rule_name=rule,
            source_siem=siem,
            entity_type="host",
            entity_value=host,
            raw_reference=f"{siem}://search?sid={uuid4().hex[:12]}",
            timestamp=ts,
            phase=tactic,
            technique_id=tech_id,
            status_contributed=pstatus,
            confidence_contribution=round(random.uniform(0.4, 0.9), 2),
        ))
        phases.append(PhaseState(
            phase=tactic,
            status=pstatus,
            technique_id=tech_id,
            technique_name=tech_name,
            first_seen=ts,
            last_seen=ts,
            evidence_ids=[ev_id],
            confidence=round(random.uniform(0.4, 0.95), 2),
        ))

    current = steps[-1][0]
    resolved_at = (opened + resolved_after) if resolved_after else None
    last_seen = resolved_at or end
    first_response = opened + timedelta(minutes=random.uniform(3, 25))

    actions = [
        ResponseAction(action_type="isolate_host", priority="immediate", target_entity=host,
                       description=f"Network-isolate {host}", automated=True, completed=terminal,
                       completed_at=resolved_at if terminal else None),
        ResponseAction(action_type="reset_credentials", priority="immediate", target_entity=user,
                       description=f"Force credential reset for {user}", automated=False,
                       completed=terminal, completed_at=resolved_at if terminal else None),
    ]

    return AttackState(
        attack_id=uuid4(),
        tenant_id=TENANT_ID,
        name=f"{label}: {host}",
        description=f"{label} activity observed on {host} ({ip}) involving {user}.",
        status=status,
        current_phase=current,
        confidence=round(confidence, 2),
        impact=ImpactLevel(impact),
        momentum=momentum,
        phases=phases,
        users=[user],
        hosts=[host, ip],
        evidence=evidence,
        narrative=(f"An attacker progressed through {len(steps)} phase(s) of the kill chain "
                   f"on {host}, beginning with {steps[0][2]}. "
                   + ("The activity was contained by automated response." if terminal
                      else "The attack is active and being worked by the SOC.")),
        predicted_next_phase=None,
        recommended_actions=actions,
        response_status=ResponseStatus(
            containment=terminal, eradication=terminal, recovery=(status == AttackStateStatus.RESOLVED),
            containment_at=resolved_at if terminal else None,
            eradication_at=resolved_at if terminal else None,
            recovery_at=resolved_at if status == AttackStateStatus.RESOLVED else None,
        ),
        first_seen=opened,
        last_seen=last_seen,
        last_updated=last_seen,
        first_response_at=first_response,
        resolved_at=resolved_at,
    )


def build_dataset() -> list:
    attacks = []

    # ── ACTIVE attacks (status=active) → Active Threats board + dashboard ──────
    # confidence buckets: critical ≥0.85, high 0.70–0.84
    active_specs = [
        # (scenario_idx, steps, conf, momentum, hours_open)
        (0, 7, 0.91, Momentum.INCREASING, 6.5),    # ransomware, critical, escalating, SLA breach
        (2, 4, 0.88, Momentum.INCREASING, 5.2),    # exfil, critical, escalating, breach
        (3, 3, 0.86, Momentum.INCREASING, 2.0),    # cloud, critical
        (1, 2, 0.79, Momentum.INCREASING, 9.0),    # cred access, high, breach
        (5, 3, 0.74, Momentum.STABLE, 1.5),        # web server, high
        (4, 2, 0.61, Momentum.STABLE, 3.0),        # phishing, medium
        (6, 2, 0.52, Momentum.DECREASING, 0.8),    # privesc, medium
        (7, 1, 0.41, Momentum.STABLE, 0.4),        # insider, low
    ]
    for idx, steps, conf, mom, hrs in active_specs:
        opened = NOW - timedelta(hours=hrs)
        attacks.append(build_attack(SCENARIOS[idx], opened=opened, n_steps=steps,
                                    status=AttackStateStatus.ACTIVE, confidence=conf,
                                    momentum=mom, resolved_after=None))

    # ── RESOLVED / CONTAINED across the trailing 30 days ──────────────────────
    # Spread opens across days; vary resolution duration to shape MTTR + SLA.
    for day in range(0, 30):
        # 0–3 resolved attacks per day, weighted toward recent days
        count = random.choice([0, 1, 1, 2, 2, 3] if day < 12 else [0, 0, 1, 1, 2])
        for _ in range(count):
            idx = random.randrange(len(SCENARIOS))
            scenario = SCENARIOS[idx]
            steps = random.randint(1, len(scenario[2]))
            opened = (NOW - timedelta(days=day)).replace(
                hour=random.randint(0, 23), minute=random.randint(0, 59))
            # resolution duration: mostly under 4h, some breaches over 4h
            if random.random() < 0.28:
                dur = timedelta(hours=random.uniform(4.2, 11))
            else:
                dur = timedelta(minutes=random.uniform(25, 220))
            # don't let resolution land in the future
            if opened + dur > NOW:
                dur = timedelta(minutes=random.uniform(20, 90))
            conf = random.choice([0.46, 0.58, 0.63, 0.72, 0.77, 0.81, 0.88, 0.93])
            status = random.choice(
                [AttackStateStatus.RESOLVED, AttackStateStatus.RESOLVED,
                 AttackStateStatus.RESOLVED, AttackStateStatus.CONTAINED])
            attacks.append(build_attack(scenario, opened=opened, n_steps=steps,
                                        status=status, confidence=conf,
                                        momentum=random.choice(list(Momentum)),
                                        resolved_after=dur))
    return attacks


async def main() -> None:
    attacks = build_dataset()
    conn = await asyncpg.connect(DATABASE_URL)

    # clean any prior seed for this tenant (idempotent re-runs)
    await conn.execute("DELETE FROM attack_state_transitions WHERE tenant_id=$1", TENANT_ID)
    await conn.execute("DELETE FROM playbook_runs WHERE tenant_id=$1", UUID(TENANT_ID))
    await conn.execute("DELETE FROM attack_states WHERE tenant_id=$1", TENANT_ID)
    await conn.execute("DELETE FROM api_keys WHERE tenant_id=$1", UUID(TENANT_ID))

    # insert attacks
    for a in attacks:
        await conn.execute(
            """INSERT INTO attack_states (attack_id, tenant_id, name, status, current_phase,
                 confidence, momentum, impact, state, first_seen, last_seen, created_at, updated_at)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,$11,$10,$11)""",
            a.attack_id, a.tenant_id, a.name, a.status.value, a.current_phase.value,
            a.confidence, a.momentum.value, a.impact.value, a.model_dump_json(),
            a.first_seen, a.last_seen,
        )
        # one transition per phase progression
        prev_phase = None
        prev_conf = 0.0
        for i, p in enumerate(a.phases):
            await conn.execute(
                """INSERT INTO attack_state_transitions (transition_id, attack_id, tenant_id,
                     previous_phase, new_phase, previous_confidence, new_confidence,
                     previous_momentum, new_momentum, trigger_signal_id, trigger_detection_id,
                     is_escalation, transition_at)
                   VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)""",
                uuid4(), a.attack_id, a.tenant_id,
                prev_phase, p.phase.value, prev_conf, p.confidence,
                Momentum.STABLE.value, a.momentum.value,
                a.evidence[i].signal_id if i < len(a.evidence) else str(uuid4()),
                a.evidence[i].detection_id if i < len(a.evidence) else None,
                i > 0 and p.confidence - prev_conf > 0.15,
                p.first_seen,
            )
            prev_phase, prev_conf = p.phase.value, p.confidence

    # ── playbook runs (Playbooks page) ────────────────────────────────────────
    # Trigger on the higher-confidence attacks; mix of run states.
    candidates = [a for a in attacks if a.confidence >= 0.7]
    random.shuffle(candidates)
    run_specs = (["completed"] * 7) + ["running", "running", "paused", "failed"]
    pb_action_lib = [
        {"action_type": "isolate_host", "description": "Quarantine endpoint via EDR"},
        {"action_type": "reset_credentials", "description": "Revoke sessions & force reset"},
        {"action_type": "block_ip", "description": "Push firewall block for C2 IP"},
        {"action_type": "disable_account", "description": "Disable compromised account"},
        {"action_type": "kill_process", "description": "Terminate malicious process tree"},
        {"action_type": "snapshot_host", "description": "Capture forensic disk snapshot"},
    ]
    for status, a in zip(run_specs, candidates):
        triggered = a.first_seen + timedelta(minutes=random.uniform(2, 18))
        n_actions = random.randint(3, 5)
        actions = random.sample(pb_action_lib, n_actions)
        if status == "completed":
            completed = actions
            completed_at = a.resolved_at or (triggered + timedelta(minutes=random.uniform(8, 40)))
        elif status == "failed":
            completed = actions[: max(1, n_actions - 2)]
            completed_at = triggered + timedelta(minutes=random.uniform(5, 20))
        elif status == "paused":
            completed = actions[: n_actions // 2]
            completed_at = None
        else:  # running
            completed = actions[: max(1, n_actions // 3)]
            completed_at = None
        await conn.execute(
            """INSERT INTO playbook_runs (run_id, attack_id, tenant_id, workflow_id, narrative_id,
                 triggered_at, status, phase_at_trigger, confidence_at_trigger, completed_at,
                 actions, completed_actions)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12::jsonb)""",
            uuid4(), a.attack_id, UUID(TENANT_ID),
            f"playbook-{a.attack_id}", f"{a.current_phase.value}-response",
            triggered, status, a.current_phase.value, a.confidence, completed_at,
            json.dumps(actions), json.dumps(completed),
        )

    # ── API key (Settings page) — a real, working key ─────────────────────────
    body = os.urandom(24).hex()
    raw_key = f"vgl_{body}"
    prefix = raw_key[:8]
    digest = hashlib.sha256(raw_key.encode()).digest()
    key_hash = bcrypt.hashpw(digest, bcrypt.gensalt(rounds=12)).decode()
    await conn.execute(
        """INSERT INTO api_keys (key_id, tenant_id, created_by, name, key_prefix, key_hash,
             scopes, last_used_at, expires_at, revoked, created_at, use_count)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)""",
        uuid4(), UUID(TENANT_ID), CREATED_BY, "Production Ingest Key", prefix, key_hash,
        ["read:attacks", "read:detections", "write:signals"],
        NOW - timedelta(hours=3), None, False, NOW - timedelta(days=9), 1487,
    )

    # summary
    active = sum(1 for a in attacks if a.status == AttackStateStatus.ACTIVE)
    await conn.close()
    print(f"Seeded {len(attacks)} attacks ({active} active), "
          f"{len(run_specs)} playbook runs, 1 API key for tenant {TENANT_ID}")
    print(f"RAW_API_KEY={raw_key}")


if __name__ == "__main__":
    asyncio.run(main())
