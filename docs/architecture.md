# VIGIL Architecture

## Core Concept

Signals don't generate alerts. They update **AttackState objects**.

Every detection answers one question: *"Where is the attacker in the kill chain, and what changed?"*

If a detection does not advance attack certainty, it does not exist.

---

## Data Flow

```
Splunk ES/Core
      │
      ▼
  Ingestor
  (CDM normalization)
      │
      ▼ vigil.signals.raw (Kafka)
      │
      ▼
  Correlation Engine
  (CDMEvent → AttackState transition)
      │
      ├─▶ vigil.attacks.created (new AttackState)
      └─▶ vigil.attacks.updated (state change)
               │
               ▼
          AI Engine
          (Claude narrative generation)
               │
               ▼
          vigil.attacks.escalated (threshold crossed)
               │
               ▼
          Analyst Portal / Playbook Engine
```

---

## AttackState Lifecycle

```
Signal arrives
  → Correlation Engine extracts entities
  → Looks up existing AttackState for those entities
  → Checks detection's state_impact
  → Updates AttackState (phase, evidence, entities)
  → Recalculates confidence + momentum
  → Publishes transition event IF state changed

confidence < 0.50  →  Background tracking (no analyst notification)
confidence 0.50–0.70  →  Analyst queue (low priority)
confidence >= 0.70  →  Escalation (analyst notified)
confidence >= 0.85  →  High confidence (recommended immediate response)
```

---

## Confidence Formula

```
confidence = (confirmed_signals × 0.50) + (supporting_signals × 0.20) + (progression_bonus × 0.30)
capped at 1.0

progression_bonus = min((distinct_confirmed_phases - 1) × 0.25, 1.0)
```

All weights are configurable per tenant.

---

## Detection-as-Code Pipeline

```
detections/yaml/           ← Engineer edits here only
  credential_access/
    D1-lsass-memory-access.yaml
    D2-lsass-dump-creation.yaml
  lateral_movement/
    D4-lateral-movement-compromised-creds.yaml

PR opened
  → validate_detections.py  (schema + ATT&CK mapping)
  → compile_detections.py   (YAML → SPL + KQL + EQL)
  → test_detections.py      (unit tests against fixtures)
  → mitre_coverage.py       (coverage diff)
  → regression_check.py     (no broken state transitions)

Merge → main
  → deploy_detections.py    (push to Splunk, Sentinel, Elastic)
  → detections/compiled/    (auto-generated, never hand-edited)
```

---

## Kafka Topics

| Topic | Description |
|---|---|
| `vigil.signals.raw` | Normalized CDMEvents from ingestor |
| `vigil.attacks.created` | New AttackState initialized |
| `vigil.attacks.updated` | Existing AttackState modified |
| `vigil.attacks.escalated` | Confidence crossed escalation threshold |
| `vigil.responses.triggered` | Playbook execution started |

---

## Tenant Isolation

- Each tenant has isolated AttackState storage (PostgreSQL row-level security)
- Kafka topics are tenant-prefixed in multi-tenant deployments
- Detection libraries can be shared (global) or tenant-specific
- Confidence thresholds are configurable per tenant
