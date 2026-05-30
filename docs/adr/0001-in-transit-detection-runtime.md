# ADR 0001 — In-transit detection runtime (Big Bet 1)

Status: Accepted (MVP shipped) · Date: 2026-05-30

## Context

VIGIL compiles detections to SIEM dialects (`signal-translation/compiler.py`
emits SPL/KQL/EQL) and pushes them **to** the customer SIEM; it never runs
detections itself. The correlation engine only sees CDM events that already
carry a `detection_id`. We want VIGIL to run "templated queries (detections) on
data in transit" so it can alert on raw telemetry directly, independent of the
SIEM.

## Decision

Build a **VIGIL-native CDM predicate runtime**, not a SIEM-dialect executor.
Detections are field predicates (`equals/contains/regex/gt/lt/in/exists` over
dotted CDM paths) AND-combined, evaluated against the normalized CDM shape — so
one rule works across every source SIEM.

Shipped (MVP):
- `services/ingestor/cdm_rules.py` — the evaluator + a starter ruleset mapping
  to curated detections (encoded PowerShell, fodhelper, sc.exe, LSASS, domain
  discovery, PsExec).
- Wired into `POST /signals` enrichment: a raw event with no `detection_id` is
  tagged with the best matching detection before publishing.
- `POST /detect/evaluate` — dry-run a CDM event against the ruleset (testing
  surface).

## Options considered

1. **VIGIL-native predicate evaluator (chosen).** Lightweight, controllable,
   reuses the existing `EventNormalizer` + CDM model. Stateless single-event
   matching today.
2. **Stream-processing engine (Flink / ksqlDB / Materialize).** Lowest latency,
   highest ops cost. Deferred — only justified once stateful/windowed detections
   (beaconing, brute force, rate) are required.
3. **Execute the compiled SIEM-dialect strings inside VIGIL.** Rejected — they
   are not portable or executable outside their SIEM.

## Consequences

- Stateful detections (beaconing, impossible-travel, thresholds over a window)
  are **out of scope** for the single-event MVP and need a windowed evaluator
  (option 2) — the natural next step.
- The rule format becomes the spine the simulation engine and Big Bet 2 build on.
- Output CDM events carry `detection_id` + `state_impact` and flow into the
  **existing** correlation pipeline unchanged.

## Sequencing

MVP predicate evaluator (done) → expand ruleset + `arms_on` chaining metadata →
windowed/stateful evaluator → dedicated stream-detection service if volume
demands it.
