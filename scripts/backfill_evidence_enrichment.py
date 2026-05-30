"""Backfill enrichment fields onto existing attack evidence (in-place).

Phase 3 added optional enrichment fields to EvidenceItem (host, ip, user,
process, command_line, dest_ip/port, severity, title, description, raw_event)
so the evidence drill-down has real context. Attacks seeded before that change
lack the fields; this script derives plausible values from what's already on
each evidence item + its attack and writes them into the state JSONB, without
recreating attacks (non-destructive).

Run:  DATABASE_URL=... [TENANT_ID=...] services/api/.venv/bin/python scripts/backfill_evidence_enrichment.py
"""

from __future__ import annotations

import asyncio
import json
import os
import random
from datetime import datetime, timezone

import asyncpg

random.seed(7)

DATABASE_URL = os.environ["DATABASE_URL"]
TENANT_ID = os.environ.get("TENANT_ID")

_PROCS = ["powershell.exe", "cmd.exe", "rundll32.exe", "lsass.exe", "wmic.exe",
          "svchost.exe", "psexec.exe", "net.exe"]
_PORTS = [445, 3389, 443, 80, 5985, 22, 135]
_SEV = ["critical", "high", "medium"]


def _is_ip(s: str) -> bool:
    return bool(s) and s.count(".") == 3 and all(p.isdigit() for p in s.split("."))


def _enrich_evidence(ev: dict, hosts: list[str], users: list[str]) -> bool:
    """Mutate one evidence dict in place. Returns True if changed."""
    if ev.get("host") or ev.get("raw_event"):
        return False  # already enriched
    ip_hosts = [h for h in hosts if _is_ip(h)]
    name_hosts = [h for h in hosts if not _is_ip(h)]
    host = ev.get("entity_value") if ev.get("entity_type") == "host" and not _is_ip(ev.get("entity_value", "")) \
        else (name_hosts[0] if name_hosts else ev.get("entity_value"))
    ip = ip_hosts[0] if ip_hosts else None
    user = users[0] if users else None
    rule = ev.get("rule_name") or ev.get("detection_id") or "Detection"
    tech = ev.get("technique_id")
    siem = ev.get("source_siem") or "splunk_es"
    proc = random.choice(_PROCS)

    ev["title"] = f"{rule} on {host}" if host else rule
    ev["description"] = (f"{rule} ({tech}) observed on {host}"
                         + (f" ({ip})" if ip else "")
                         + (f" involving {user}" if user else "") + ".")
    ev["severity"] = random.choice(_SEV)
    ev["host"] = host
    ev["ip"] = ip
    ev["user"] = user
    ev["process"] = proc
    ev["command_line"] = f"{proc} " + random.choice([
        "-enc SQBFAFgA", "/c whoami /priv", "-noP -w hidden", "x.dll,Start",
        r"\\admin$\svc.exe", "user /domain",
    ])
    ev["dest_ip"] = random.choice(ip_hosts) if ip_hosts else None
    ev["dest_port"] = random.choice(_PORTS)
    ev["raw_event"] = {
        "_time": ev.get("timestamp"),
        "host": host, "src_ip": ip, "user": user,
        "signature": rule, "technique": tech,
        "sourcetype": f"{siem}:notable", "action": "allowed",
    }
    return True


async def main() -> None:
    conn = await asyncpg.connect(DATABASE_URL)
    where = "WHERE tenant_id=$1" if TENANT_ID else ""
    args = [TENANT_ID] if TENANT_ID else []
    rows = await conn.fetch(f"SELECT attack_id, state FROM attack_states {where}", *args)

    attacks_changed = ev_changed = 0
    for r in rows:
        state = r["state"]
        if isinstance(state, str):
            state = json.loads(state)
        hosts = state.get("hosts") or []
        users = state.get("users") or []
        changed = False
        for ev in (state.get("evidence") or []):
            if isinstance(ev, dict) and _enrich_evidence(ev, hosts, users):
                changed = True
                ev_changed += 1
        if changed:
            await conn.execute(
                "UPDATE attack_states SET state=$1::jsonb WHERE attack_id=$2",
                json.dumps(state), r["attack_id"],
            )
            attacks_changed += 1

    await conn.close()
    print(f"Enriched {ev_changed} evidence items across {attacks_changed} attacks "
          f"(of {len(rows)} scanned).")


if __name__ == "__main__":
    asyncio.run(main())
