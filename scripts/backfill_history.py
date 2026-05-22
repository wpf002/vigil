"""One-off demo backfill: insert 30 days of historical RESOLVED attacks for a
tenant so the Executive Dashboard's MTTR Trend and SLA Breach Rate (30d) charts
render a real curve. Clones existing attack `state` JSON as templates and varies
timestamps / confidence / resolution time. Emits SQL to stdout (pipe to psql)."""
from __future__ import annotations
import json, random, subprocess, sys
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import os
TENANT = os.getenv("BACKFILL_TENANT", "05e12d2b-d559-4c08-b6d7-9affabf556ac")
random.seed(7)

# Pull a handful of real states as templates.
out = subprocess.run(
    ["docker", "exec", "-i", "vigil-postgres-1", "psql", "-U", "vigil", "-d", "vigil",
     "-t", "-A", "-c",
     f"select state from attack_states where tenant_id='{TENANT}' order by confidence desc limit 6;"],
    capture_output=True, text=True, check=True,
)
templates = [json.loads(l) for l in out.stdout.splitlines() if l.strip()]
if not templates:
    print("-- no templates found", file=sys.stderr); sys.exit(1)

SLA = 4 * 3600  # 4h breach threshold (matches reporting aggregator)
now = datetime.now(timezone.utc)
midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)

def iso(dt): return dt.isoformat().replace("+00:00", "Z")

rows = []
# Days 29..1 ago (skip today — today already has the live seeded attacks).
for d in range(29, 0, -1):
    day = midnight - timedelta(days=d)
    for _ in range(random.randint(2, 4)):
        t = json.loads(json.dumps(random.choice(templates)))  # deep copy
        aid = str(uuid4())
        opened = day + timedelta(hours=random.randint(1, 20), minutes=random.randint(0, 59))
        # ~30% breach SLA (>4h), rest resolve 20min–3.5h.
        mttr = random.randint(int(4.2 * 3600), int(11 * 3600)) if random.random() < 0.30 \
            else random.randint(20 * 60, int(3.5 * 3600))
        resolved = opened + timedelta(seconds=mttr)
        conf = round(random.uniform(0.70, 0.96), 2)
        t.update({
            "attack_id": aid, "tenant_id": TENANT, "status": "resolved",
            "confidence": conf, "first_seen": iso(opened), "last_seen": iso(resolved),
            "last_updated": iso(resolved), "resolved_at": iso(resolved),
        })
        rows.append((aid, t["name"], t.get("current_phase", "credential-access"),
                     conf, t.get("impact", "High"), t.get("momentum", "Stable"),
                     iso(opened), iso(resolved), json.dumps(t)))

print("BEGIN;")
for aid, name, phase, conf, impact, momentum, fs, ls, state_json in rows:
    name_sql = name.replace("'", "''")
    print(
        "INSERT INTO attack_states (attack_id, tenant_id, name, status, current_phase, "
        "confidence, impact, momentum, first_seen, last_seen, created_at, updated_at, state) VALUES ("
        f"'{aid}', '{TENANT}', '{name_sql}', 'resolved', '{phase}', {conf}, '{impact}', "
        f"'{momentum}', '{fs}', '{ls}', '{fs}', '{ls}', $vigil${state_json}$vigil$);"
    )
print("COMMIT;")
print(f"-- generated {len(rows)} historical attacks", file=sys.stderr)
