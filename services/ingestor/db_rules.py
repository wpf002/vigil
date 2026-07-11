"""Load tenant-authored detection rules from the shared DB for in-transit
evaluation.

Detections authored in the UI store their logic as `conditions` inside the
detection_versions.state_impact JSONB. This loader turns each active detection
with conditions into a CDMRule so the ingestor's evaluator matches on it,
alongside the built-in DEFAULT_RULES.

Results are cached per tenant with a short TTL so we don't hit Postgres on
every event. Any DB error degrades gracefully to the last good (or empty) set.
"""

from __future__ import annotations

import json
import time
from typing import Any, Optional

from .cdm_rules import CDMRule, rule_from_conditions

_TTL_SECONDS = 60.0
_CACHE: dict[str, tuple[float, list[CDMRule]]] = {}


async def rules_for_tenant(pool: Any, tenant_id: str) -> list[CDMRule]:
    if pool is None or not tenant_id:
        return []

    now = time.monotonic()
    cached = _CACHE.get(tenant_id)
    if cached and cached[0] > now:
        return cached[1]

    try:
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT detection_id, att_ck_tactic, att_ck_technique, state_impact
                  FROM detection_versions
                 WHERE tenant_id = $1::uuid AND status = 'active'
                """,
                str(tenant_id),
            )
    except Exception:
        # Don't let a DB hiccup break ingestion — reuse last good set if any.
        return cached[1] if cached else []

    rules: list[CDMRule] = []
    for r in rows:
        si: Any = r["state_impact"]
        if isinstance(si, str):
            try:
                si = json.loads(si)
            except json.JSONDecodeError:
                si = {}
        si = si or {}
        rule = rule_from_conditions(
            detection_id=r["detection_id"],
            name=r["detection_id"],
            conditions=si.get("conditions") or [],
            tactic=r["att_ck_tactic"],
            technique_id=r["att_ck_technique"] or None,
            confidence=_as_float(si.get("confidence_contribution"), 0.6),
            status=si.get("status") or "Observed",
        )
        if rule is not None:
            rules.append(rule)

    _CACHE[tenant_id] = (now + _TTL_SECONDS, rules)
    return rules


def _as_float(v: Any, default: float) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return default
