# VIGIL

AI-native, SIEM-agnostic security operations platform that replaces alert queues with persistent, deterministic attack-state narratives.

Ingests and normalizes telemetry from Splunk, Sentinel, and Elastic through a detection-as-code YAML layer that compiles to SPL/KQL/EQL, correlates signals into confidence-scored MITRE-mapped AttackState objects, and leverages Claude to reason over attack progression and generate actionable response recommendations — without vendor lock-in.

---

## Who It Beats and Why

| Platform              | Their weakness                                          | VIGIL's answer                                              |
| --------------------- | ------------------------------------------------------- | ----------------------------------------------------------- |
| ReliaQuest GreyMatter | Black box, vendor-owned detections, enterprise pricing  | Transparent logic, engineer-owned YAML, mid-market pricing  |
| Splunk ES             | Alert chaos, no narrative, no state model               | Attack-state engine gates noise, enforces progression       |
| Microsoft Sentinel    | Cloud-locked, no cross-platform portability             | SIEM-agnostic YAML compiles to SPL/KQL/EQL equally          |

---

## Core Concept

Every detection answers one question: **"Where is the attacker in the kill chain, and what changed?"**

Signals don't generate alerts. They update **AttackState objects** — live attack narratives that track adversary progression, confidence, momentum, and recommended response. Analysts work 12 attack narratives, not 200 alerts.

---

## Architecture

```text
┌─────────────────────────────────────────────────────────────────────┐
│                         VIGIL PLATFORM                              │
├──────────────┬──────────────────────┬──────────────────────────────┤
│  INGEST &    │  DETECTION           │  ATTACK OPERATIONS           │
│  SIGNAL      │  LAYER               │                              │
│  LAYER       │                      │  ┌──────────────────────┐    │
│              │  YAML Detection      │  │  ATTACK-STATE ENGINE │    │
│  Splunk ES   │  Definitions         │  │                      │    │
│  Splunk Core │  (source of truth)   │  │  AttackState objects │    │
│  Sentinel    │        │             │  │  Phase tracking      │    │
│  Elastic     │        ▼             │  │  Confidence scoring  │    │
│  HEC Bridge  │  Signal Translation  │  │  Momentum calculation│    │
│              │  Engine              │  │  Entity graph        │    │
│  CDM Layer   │  SPL / KQL / EQL     │  └──────────┬───────────┘    │
│              │  (identical intent)  │             │                │
│              │        │             │             ▼                │
│              │        ▼             │  AI NARRATIVE ENGINE         │
│              │  Attack Correlation  │  (Claude)                    │
│              │  Engine              │  Attack story generation     │
│              │  (state-gated,       │  NL threat hunting           │
│              │   no single-signal   │  Response recommendation     │
│              │   alerts)            │  Detection writing assist    │
├──────────────┴──────────────────────┴──────────────────────────────┤
│                         PLATFORM CORE                               │
│     Multi-tenancy | RBAC | API Gateway | Audit Logs | Billing       │
├─────────────────────────────────────────────────────────────────────┤
│                    CONTROL PLANE (CI/CD)                            │
│   YAML validation | ATT&CK coverage | Testing | Rollback | Diffing  │
├─────────────────────────────────────────────────────────────────────┤
│                    MANAGED SERVICE LAYER                            │
│        Analyst Portal | SLA Tracking | Shift Management             │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Services

| Service               | Description                                                                | Port |
| --------------------- | -------------------------------------------------------------------------- | ---- |
| `api`                 | Core FastAPI backend — auth, tenancy, RBAC, API keys, webhooks, audit log  | 8000 |
| `ingestor`            | Splunk / Sentinel / Elastic connector, CDM normalization, Kafka producer   | 8001 |
| `attack-state-engine` | AttackState persistence, confidence scoring, momentum tracking             | 8002 |
| `correlation-engine`  | Maps CDM events → AttackState transitions                                  | 8003 |
| `signal-translation`  | YAML detection → SPL/KQL/EQL compilation                                   | 8004 |
| `detection-engine`    | YAML detection registry + marketplace, control plane                       | 8005 |
| `ai-engine`           | Claude-powered narrative generation, hunting, response                     | 8006 |
| `playbook-engine`     | Temporal-backed response workflow orchestration (XSOAR + Tines)            | 8007 |
| `analyst-portal`      | Managed service analyst tooling                                            | 8008 |
| `reporting`           | Executive dashboard + SOC 2 / PCI / NIST evidence packs                    | 8009 |
| `frontend`            | React + TypeScript SOC interface                                           | 5173 |
| `mobile`              | iOS analyst app (pure React Native, no Expo)                               | —    |

---

## Tech Stack

| Layer                | Tech                                                |
| -------------------- | --------------------------------------------------- |
| Backend services     | Python 3.12 + FastAPI                               |
| Frontend             | React 18 + TypeScript + Tailwind                    |
| SIEM connectors      | Splunk SDK/REST, Sentinel API, Elastic Python client|
| Event streaming      | Apache Kafka                                        |
| App database         | PostgreSQL 16                                       |
| Cache                | Redis 7                                             |
| Event/state storage  | Elasticsearch 8                                     |
| AI                   | Anthropic Claude API                                |
| Detection format     | Custom YAML (source of truth) → SPL / KQL / EQL     |
| Workflow engine      | Temporal.io                                         |
| Auth                 | Custom JWT (HS256) + bcrypt                         |
| Infra                | AWS (EKS, RDS, MSK, S3)                             |
| Containers           | Docker + Kubernetes                                 |
| CI/CD                | GitHub Actions                                      |

---

## Detection-as-Code

All detections live in `detections/yaml/` as YAML files. Never edit `detections/compiled/` — it's auto-generated.

Push a branch, open a PR:

1. YAML schema validated
2. ATT&CK mapping verified
3. Compiled to SPL + KQL + EQL
4. Unit tested against synthetic telemetry
5. AttackState transition logic tested
6. ATT&CK coverage diff generated
7. Merge → auto-deployed to all configured SIEM tenants

---

## Kafka Topics

| Topic                       | Producer            | Consumer                          |
| --------------------------- | ------------------- | --------------------------------- |
| `vigil.signals.raw`         | ingestor            | correlation-engine                |
| `vigil.attacks.created`     | correlation-engine  | ai-engine, analyst-portal         |
| `vigil.attacks.updated`     | correlation-engine  | ai-engine, analyst-portal         |
| `vigil.attacks.escalated`   | attack-state-engine | analyst-portal, playbook-engine   |
| `vigil.responses.triggered` | playbook-engine     | analyst-portal                    |

---

## Getting Started

### Prerequisites

- Python 3.12+
- Node.js 20+
- Docker + Docker Compose

### Bootstrap

```bash
chmod +x scripts/bootstrap.sh
./scripts/bootstrap.sh
```

### Start infrastructure

```bash
docker-compose up -d
```

### Apply database migrations

Each service owns its schema in `services/<svc>/migrations/`. Apply them in
this order against the local Postgres (port 5433):

```bash
PGPASSWORD=changeme psql -h localhost -p 5433 -U vigil -d vigil \
  -f services/api/migrations/001_auth.sql \
  -f services/api/migrations/002_api_keys.sql \
  -f services/api/migrations/003_onboarding.sql \
  -f services/api/migrations/004_audit_log.sql \
  -f services/attack-state-engine/migrations/001_initial.sql \
  -f services/detection-engine/migrations/001_detection_engine.sql \
  -f services/detection-engine/migrations/002_marketplace.sql \
  -f services/playbook-engine/migrations/001_playbooks.sql \
  -f services/analyst-portal/migrations/001_analyst_portal.sql \
  -f services/reporting/migrations/001_reporting.sql
```

### Run a service

```bash
cd services/ingestor
source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8001
```

---

## Build Status

| Service              | Status                                                                                                    |
| -------------------- | --------------------------------------------------------------------------------------------------------- |
| `ingestor`           | ✅ Complete — Splunk ES + Core + Sentinel + Elastic connectors, CDM, Kafka producer, 37 tests             |
| `attack-state-engine`| ✅ Complete — AttackState persistence, JWT auth, narrative PATCH, 28 tests                                |
| `correlation-engine` | ✅ Complete — Kafka consumer, entity index, manifest-driven registry, 12 tests                            |
| `api`                | ✅ Complete — JWT auth, API keys, webhooks, onboarding, audit log, 39 tests                               |
| `signal-translation` | ✅ Complete — YAML compiler, field normalization, ATT&CK coverage, 12 tests                               |
| `ai-engine`          | ✅ Complete — Claude narrative generator, prompt caching, Redis cache, 11 tests                           |
| `frontend`           | ✅ Complete — Auth, attacks, detections, marketplace, dashboard, compliance, settings, onboarding         |
| `detection-engine`   | ✅ Complete — Detection registry, marketplace, FP-rate performance, ATT&CK coverage, rollback, 23 tests   |
| `playbook-engine`    | ✅ Complete — Temporal workflow, XSOAR + Tines SOAR backends, escalation consumer, 17 tests               |
| `analyst-portal`     | ✅ Complete — Escalation queue, SLA monitor, analyst actions, shifts, role-gated, 15 tests                |
| `reporting`          | ✅ Complete — Executive summary, trends, SOC 2 / PCI / NIST evidence packs, daily snapshots, 9 tests      |
| `vigil-sdk` (Python) | ✅ Complete — Public API client, dataclass models, webhook signature verification, 18 tests               |
| `mobile`             | ✅ Complete — iOS analyst app, Login/Queue/Detail/Attack/Settings, Keychain token storage                 |
| `docs-site`          | ✅ Complete — Static docs (Overview, Getting Started, Architecture, Detections, API, SDK, Compliance)     |

---

## License

Proprietary. All rights reserved.
