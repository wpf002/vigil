"""Generate realistic detection_signals for a tenant over the trailing 30 days.

A freshly-seeded tenant has attack_states but no detection_signals, so its
Detections -> Performance page shows no fires / no FP rate. This populates a
plausible fire history (varied per-detection volume; a fraction linked to the
tenant's attacks so the escalations metric is non-zero), against the curated
detection set that the Detections library shows via the platform fallback.

After running this, run scripts/seed_detection_perf.py (same TENANT_ID) to mark
a realistic false-positive fraction and compute the performance rollups.

Run:  DATABASE_URL=... TENANT_ID=<uuid> services/api/.venv/bin/python scripts/seed_detection_signals.py
"""

from __future__ import annotations

import asyncio
import os
import random
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import asyncpg

RANDOM_SEED = 1337
random.seed(RANDOM_SEED)

DATABASE_URL = os.environ["DATABASE_URL"]
TENANT_ID = UUID(os.environ["TENANT_ID"])
PLATFORM_TENANT = UUID("00000000-0000-0000-0000-000000000000")
NOW = datetime.now(timezone.utc)

# 30-day fire volume per detection — noisy behavioral/recon rules fire a lot,
# precise signatures rarely. Unknown detections fall back to DEFAULT_VOLUME.
VOLUME: dict[str, int] = {
    "D1-LSASS-MEMORY-ACCESS": 420,
    "D2-LSASS-DUMP-CREATION": 75,
    "D3-CREDENTIAL-REUSE-ANOMALY": 980,
    "D4-LATERAL-MOVEMENT-COMPROMISED-CREDS": 310,
    "D5-POWERSHELL-ENCODED-COMMAND": 540,
    "D6-NEW-SERVICE-INSTALL": 260,
    "D7-UAC-BYPASS-FODHELPER": 60,
    "D8-DOMAIN-ACCOUNT-DISCOVERY": 720,
    "D9-WEB-PROTOCOL-BEACONING": 480,
    "D10-EXFIL-ALTERNATIVE-PROTOCOL": 140,
}
DEFAULT_VOLUME = 300

TACTIC: dict[str, str] = {
    "D1-LSASS-MEMORY-ACCESS": "credential-access",
    "D2-LSASS-DUMP-CREATION": "credential-access",
    "D3-CREDENTIAL-REUSE-ANOMALY": "credential-access",
    "D4-LATERAL-MOVEMENT-COMPROMISED-CREDS": "lateral-movement",
    "D5-POWERSHELL-ENCODED-COMMAND": "execution",
    "D6-NEW-SERVICE-INSTALL": "persistence",
    "D7-UAC-BYPASS-FODHELPER": "privilege-escalation",
    "D8-DOMAIN-ACCOUNT-DISCOVERY": "discovery",
    "D9-WEB-PROTOCOL-BEACONING": "command-and-control",
    "D10-EXFIL-ALTERNATIVE-PROTOCOL": "exfiltration",
}

ESCALATION_FRACTION = 0.12  # share of signals linked to a real attack_id


async def main() -> None:
    conn = await asyncpg.connect(DATABASE_URL)

    detections = [
        r["detection_id"]
        for r in await conn.fetch(
            "SELECT detection_id FROM detection_versions "
            "WHERE tenant_id=$1 AND status='active' ORDER BY detection_id",
            PLATFORM_TENANT,
        )
    ]
    if not detections:
        raise SystemExit("no curated/platform detections found to attribute signals to")

    attack_ids = [
        r["attack_id"]
        for r in await conn.fetch(
            "SELECT attack_id FROM attack_states WHERE tenant_id=$1", str(TENANT_ID)
        )
    ]

    # idempotent: clear this tenant's prior signals + perf
    await conn.execute("DELETE FROM detection_signals WHERE tenant_id=$1", TENANT_ID)
    await conn.execute("DELETE FROM detection_performance WHERE tenant_id=$1", TENANT_ID)

    records: list[tuple] = []
    for det in detections:
        vol = VOLUME.get(det, DEFAULT_VOLUME)
        tactic = TACTIC.get(det)
        for _ in range(vol):
            fired_at = NOW - timedelta(
                days=random.uniform(0, 30),
                seconds=random.uniform(0, 86_400),
            )
            attack_id = (
                random.choice(attack_ids)
                if attack_ids and random.random() < ESCALATION_FRACTION
                else None
            )
            records.append((
                uuid4(),                                   # signal_id
                det,                                       # detection_id
                TENANT_ID,                                 # tenant_id
                fired_at,                                  # fired_at
                attack_id,                                 # attack_id
                tactic,                                    # phase_contributed
                random.choice(["Observed", "Confirmed"]),  # status_contributed
                round(random.uniform(0.4, 0.95), 2),       # confidence_contribution
                False,                                     # was_false_positive
                None,                                      # closed_as
            ))

    await conn.copy_records_to_table(
        "detection_signals",
        records=records,
        columns=[
            "signal_id", "detection_id", "tenant_id", "fired_at", "attack_id",
            "phase_contributed", "status_contributed", "confidence_contribution",
            "was_false_positive", "closed_as",
        ],
    )
    await conn.close()
    print(f"Inserted {len(records)} detection_signals for tenant {TENANT_ID} "
          f"across {len(detections)} detections.")
    print("Next: run scripts/seed_detection_perf.py with the same TENANT_ID to "
          "mark FPs and compute performance rollups.")


if __name__ == "__main__":
    asyncio.run(main())
