# VIGIL

AI-native, SIEM-agnostic security operations platform that replaces alert queues with persistent, deterministic attack-state narratives.

Ingests and normalizes telemetry from Splunk, Sentinel, and Elastic through a detection-as-code YAML layer that compiles to SPL/KQL/EQL, correlates signals into confidence-scored MITRE-mapped AttackState objects, and leverages Claude to reason over attack progression and generate actionable response recommendations — without vendor lock-in.

---

## Who It Beats and Why

| Platform | Their weakness | VIGIL's answer |
|---|---|---|
| ReliaQuest GreyMatter | Black box, vendor-owned detections, enterprise pricing | Transparent logic, engineer-owned YAML, mid-market pricing |
| Splunk ES | Alert chaos, no narrative, no state model | Attack-state engine gates noise, enforces progression |
| Microsoft Sentinel | Cloud-locked, no cross-platform portability | SIEM-agnostic YAML compiles to SPL/KQL/EQL equally |

---

## Core Concept

Every detection answers one question: **"Where is the attacker in the kill chain, and what changed?"**

Signals don't generate alerts. They update **AttackState objects** — live attack narratives that track adversary progression, confidence, momentum, and recommended response. Analysts work 12 attack narratives, not 200 alerts.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         VIGIL PLATFORM                              │
├──────────────┬──────────────────────┬──────────────────────────────┤
│  INGEST &    │  DETECTION           │  ATTACK OPERATIONS           │
│  SIGNAL      │  LAYER               │                              │
│  LAYER       │                      │  ┌──────────────────────┐   │
│              │  YAML Detection      │  │  ATTACK-STATE ENGINE  │   │
│  Splunk ES   │  Definitions         │  │                       │   │
│  Splunk Core │  (source of truth)   │  │  AttackState objects  │   │
│  Sentinel    │        │             │  │  Phase tracking       │   │
│  Elastic     │        ▼             │  │  Confidence scoring   │   │
│  HEC Bridge  │  Signal Translation  │  │  Momentum calculation │   │
│              │  Engine              │  │  Entity graph         │   │
│  CDM Layer   │  SPL / KQL / EQL     │  └──────────┬────────────┘   │
│              │  (identical intent)  │             │                 │
│              │        │             │             ▼                 │
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

| Service | Description | Port |
|---|---|---|
| `api` | Core FastAPI backend — auth, tenancy, RBAC | 8000 |
| `ingestor` | Splunk/Sentinel/Elastic connector, CDM normalization, Kafka producer | 8001 |
| `attack-state-engine` | AttackState persistence, confidence scoring, momentum tracking | 8002 |
| `correlation-engine` | Maps CDM events → AttackState transitions | 8003 |
| `signal-translation` | YAML detection → SPL/KQL/EQL compilation | 8004 |
| `detection-engine` | YAML detection registry, control plane | 8005 |
| `ai-engine` | Claude-powered narrative generation, hunting, response | 8006 |
| `playbook-engine` | Temporal-backed response workflow orchestration | 8007 |
| `analyst-portal` | Managed service analyst tooling | 8008 |
| `frontend` | React + TypeScript SOC interface | 3000 |

---

## Tech Stack

| Layer | Tech |
|---|---|
| Backend services | Python 3.12 + FastAPI |
| Frontend | React 18 + TypeScript + Tailwind |
| SIEM connectors | Splunk SDK/REST, Sentinel API, Elastic Python client |
| Event streaming | Apache Kafka |
| App database | PostgreSQL 16 |
| Cache | Redis 7 |
| Event/state storage | Elasticsearch 8 |
| AI | Anthropic Claude API |
| Detection format | Custom YAML (source of truth) → SPL / KQL / EQL |
| Workflow engine | Temporal.io |
| Auth | Clerk |
| Infra | AWS (EKS, RDS, MSK, S3) |
| Containers | Docker + Kubernetes |
| CI/CD | GitHub Actions |

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

| Topic | Producer | Consumer |
|---|---|---|
| `vigil.signals.raw` | ingestor | correlation-engine |
| `vigil.attacks.created` | correlation-engine | ai-engine, analyst-portal |
| `vigil.attacks.updated` | correlation-engine | ai-engine, analyst-portal |
| `vigil.attacks.escalated` | attack-state-engine | analyst-portal, playbook-engine |
| `vigil.responses.triggered` | playbook-engine | analyst-portal |

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
  -f services/api/migrations/001_auth.sql

PGPASSWORD=changeme psql -h localhost -p 5433 -U vigil -d vigil \
  -f services/attack-state-engine/migrations/001_initial.sql

PGPASSWORD=changeme psql -h localhost -p 5433 -U vigil -d vigil \
  -f services/detection-engine/migrations/001_detection_engine.sql

PGPASSWORD=changeme psql -h localhost -p 5433 -U vigil -d vigil \
  -f services/playbook-engine/migrations/001_playbooks.sql

PGPASSWORD=changeme psql -h localhost -p 5433 -U vigil -d vigil \
  -f services/analyst-portal/migrations/001_analyst_portal.sql
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

| Service | Status |
|---|---|
| `ingestor` | ✅ Complete — Splunk ES + Core connectors, CDM, Kafka producer, 20 tests |
| `attack-state-engine` | ✅ Complete — AttackState persistence, JWT auth, narrative PATCH, 28 tests |
| `correlation-engine` | ✅ Complete — Kafka consumer, entity index, manifest-driven registry, 12 tests |
| `api` | ✅ Complete — Custom JWT auth (HS256 + bcrypt + refresh rotation), tenants, RBAC, 16 tests |
| `signal-translation` | ✅ Complete — YAML compiler, field normalization, ATT&CK coverage, 12 tests |
| `ai-engine` | ✅ Complete — Claude narrative generator, prompt caching, Redis cache, 11 tests |
| `frontend` | ✅ Complete — Auth flows, AttackList/AttackDetail, narrative UI, detections + playbooks pages |
| `detection-engine` | ✅ Complete — Detection registry, version history, FP-rate performance, ATT&CK coverage, rollback, 15 tests |
| `playbook-engine` | ✅ Complete — Temporal-backed response workflow, narrative loader, escalation consumer, 7 tests |
| `analyst-portal` | ✅ Complete — Escalation queue, SLA monitor, analyst actions, shifts, role-gated to vigil_analyst/vigil_admin, 15 tests |

---

## License

Proprietary. All rights reserved.
