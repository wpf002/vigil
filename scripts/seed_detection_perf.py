"""Seed realistic detection performance (fp_rate) from existing signals.

The demo pipeline writes detection_signals but never marks any as false
positives and never rolls them up under the tenant that owns the fires, so
the Detections -> Performance view shows 0% / no-data for everything.

This script, for every (tenant, detection) that has signals (optionally
scoped to one TENANT_ID):
  1. assigns the detection a realistic target FP rate (noisy anomaly/behavioral
     rules higher, high-fidelity signatures lower),
  2. marks ~that fraction of its signals was_false_positive=TRUE (idempotent:
     resets the detection's flags first, so re-runs converge to the same rate),
  3. recomputes fresh 7d and 30d detection_performance rollups from the signals
     (deleting that detection's prior rollups so latest_performance is clean).

Run:  services/api/.venv/bin/python scripts/seed_detection_perf.py
Env:  DATABASE_URL (required); TENANT_ID (optional — limit to one tenant)
"""

from __future__ import annotations

import asyncio
import os
import random
from datetime import datetime, timedelta, timezone

import asyncpg

RANDOM_SEED = 42
random.seed(RANDOM_SEED)

DATABASE_URL = os.environ["DATABASE_URL"]
TENANT_ID = os.environ.get("TENANT_ID")  # optional scope

NOW = datetime.now(timezone.utc)

# Per-detection target false-positive rate. Behavioral/anomaly rules are noisy;
# precise signatures are high-fidelity. Unknown detections fall back to DEFAULT.
FP_PROFILE: dict[str, float] = {
    "D1-LSASS-MEMORY-ACCESS": 0.09,             # EDR LSASS reads — some legit AV/EDR
    "D2-LSASS-DUMP-CREATION": 0.03,             # high-fidelity
    "D3-CREDENTIAL-REUSE-ANOMALY": 0.22,        # anomaly — noisy
    "D4-LATERAL-MOVEMENT-COMPROMISED-CREDS": 0.12,
    "D5-POWERSHELL-ENCODED-COMMAND": 0.18,      # admins legitimately use encoded PS
    "D6-NEW-SERVICE-INSTALL": 0.15,
    "D7-UAC-BYPASS-FODHELPER": 0.04,            # high-fidelity
    "D8-DOMAIN-ACCOUNT-DISCOVERY": 0.20,        # recon — noisy
    "D9-WEB-PROTOCOL-BEACONING": 0.16,
    "D10-EXFIL-ALTERNATIVE-PROTOCOL": 0.07,
}
DEFAULT_FP = 0.10


def target_fp_rate(detection_id: str) -> float:
    base = FP_PROFILE.get(detection_id, DEFAULT_FP)
    # small deterministic jitter so rates aren't suspiciously round
    return max(0.0, min(0.6, base + random.uniform(-0.02, 0.02)))


async def main() -> None:
    conn = await asyncpg.connect(DATABASE_URL)

    where_tenant = "AND tenant_id = $1" if TENANT_ID else ""
    args = [TENANT_ID] if TENANT_ID else []
    pairs = await conn.fetch(
        f"""SELECT tenant_id, detection_id, COUNT(*) AS n
              FROM detection_signals
             WHERE TRUE {where_tenant}
             GROUP BY tenant_id, detection_id
             ORDER BY tenant_id, detection_id""",
        *args,
    )

    total_marked = 0
    for p in pairs:
        tenant_id = p["tenant_id"]
        detection_id = p["detection_id"]
        n = p["n"]
        rate = target_fp_rate(detection_id)
        to_mark = round(n * rate)

        # 1. reset this detection's flags (idempotent re-runs)
        await conn.execute(
            "UPDATE detection_signals SET was_false_positive=FALSE, closed_as=NULL "
            "WHERE tenant_id=$1 AND detection_id=$2",
            tenant_id, detection_id,
        )
        # 2. mark a random sample as false positive
        if to_mark > 0:
            await conn.execute(
                """UPDATE detection_signals
                      SET was_false_positive=TRUE, closed_as='false_positive'
                    WHERE signal_id = ANY(
                        SELECT signal_id FROM detection_signals
                         WHERE tenant_id=$1 AND detection_id=$2
                         ORDER BY random() LIMIT $3
                    )""",
                tenant_id, detection_id, to_mark,
            )
        total_marked += to_mark

        # 3. recompute fresh 7d + 30d rollups (clear old rows first)
        await conn.execute(
            "DELETE FROM detection_performance WHERE tenant_id=$1 AND detection_id=$2",
            tenant_id, detection_id,
        )
        for window_days in (7, 30):
            period_start = NOW - timedelta(days=window_days)
            agg = await conn.fetchrow(
                """SELECT
                       COUNT(*)                                       AS total_fires,
                       COUNT(*) FILTER (WHERE was_false_positive)     AS false_positives,
                       COUNT(*) FILTER (WHERE NOT was_false_positive) AS true_positives,
                       COUNT(*) FILTER (WHERE attack_id IS NOT NULL)  AS escalations,
                       AVG(confidence_contribution)                   AS avg_confidence
                     FROM detection_signals
                    WHERE detection_id=$1 AND tenant_id=$2
                      AND fired_at >= $3 AND fired_at < $4""",
                detection_id, tenant_id, period_start, NOW,
            )
            total_fires = int(agg["total_fires"] or 0)
            false_positives = int(agg["false_positives"] or 0)
            fp_rate = (false_positives / total_fires) if total_fires > 0 else None
            avg_conf = float(agg["avg_confidence"]) if agg["avg_confidence"] is not None else None
            await conn.execute(
                """INSERT INTO detection_performance (
                       detection_id, tenant_id, period_start, period_end,
                       total_fires, false_positives, true_positives, escalations,
                       fp_rate, avg_confidence)
                   VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)""",
                detection_id, tenant_id, period_start, NOW,
                total_fires, false_positives, int(agg["true_positives"] or 0),
                int(agg["escalations"] or 0), fp_rate, avg_conf,
            )
        print(f"  {str(tenant_id)[:8]} {detection_id:38} n={n:5} fp~{rate*100:4.1f}% marked={to_mark}")

    await conn.close()
    print(f"Done. Marked {total_marked} signals as false-positive across {len(pairs)} (tenant,detection) pairs.")


if __name__ == "__main__":
    asyncio.run(main())
