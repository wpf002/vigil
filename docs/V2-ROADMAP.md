# VIGIL V2 Roadmap — Code-Grounded Plan

> Generated 2026-05-29 from a codebase-grounded analysis of the 30 roadmap items.
> Each item is classified (bug / UI polish / question / feature / architecture), traced to the
> files that own it, effort-estimated (S/M/L/XL), and the open questions are answered directly
> from the code. This is a planning artifact — no code was changed to produce it.

## 1. Answers to open questions

**What does SLA Breach Rate mean?**
The fraction (shown as %) of high-confidence attacks (confidence >= 0.7) that breached a fixed **4-hour** SLA measured from `opened_at` to `resolved_at`. An attack is a breach if it resolved in >4h, or is still open and has been open >4h. Formula `sla_breaches / sla_total`, rounded to 4 decimals, displayed `value*100` with 1 decimal (`services/reporting/aggregator.py:196-222`; FE `frontend/src/pages/ExecutiveDashboard.tsx:60-67`).
**Caveat / bug:** when the analyst-portal `/queue` is reachable, `_collect_escalations` (`aggregator.py:248-262`) **overwrites** `sla_breach_rate_7d` with `breaches/len(queue)` using each item's own `sla_breached` flag — a different definition with no 4h/0.7 logic. The headline KPI silently flips definition based on service availability; this must be reconciled to one source of truth.

**What does Coverage Score mean?**
The percentage of the **14 MITRE ATT&CK Enterprise tactics** that have at least one active detection mapped to them. Formula `covered_tactics / 14`, where a tactic is covered if `>=1` active detection has that `att_ck_tactic` (`services/detection-engine/coverage.py:14-60`; FE `ExecutiveDashboard.tsx:68-75`). It measures **breadth, not depth** — 50 detections on one tactic still scores 1/14 ≈ 7%. It does not weight by technique count, detection quality, or FP rate; detections with no/invalid tactic land in `unmapped_detections` and don't raise the score.

**Marketplace — what does Import do?**
Import copies a listing into the importing tenant's own library. It (a) recompiles the listing YAML to SPL/KQL/EQL via signal-translation `/compile` (best-effort), (b) writes a new **ACTIVE** `detection_versions` row for your tenant under the listing's **original** `detection_id`, deprecating any prior active version of that id, and (c) records a `marketplace_imports` audit row and bumps the download count once per tenant (`services/detection-engine/main.py:466-529`; `store.py:39-92`; `marketplace_store.py:188-250`). There is **no draft/review step** — imported logic goes live immediately. Two latent issues: detection_id collisions silently overwrite an existing same-id detection; and Import uses `get_principal` (any authenticated user) while publish/withdraw use `require_admin` (`main.py:469` vs `434/535`).

**Marketplace — what does Publish do / should it be import/export?**
Publish (admin-only, `main.py:431-463`) copies a tenant's current active detection YAML into the shared multi-tenant `marketplace_listings` (`is_curated=false`) so **other** tenants can Import it. Curated D1–D4 are seeded separately with `is_curated=true` (`main.py:154-182`). It is a real publish/subscribe sharing model, not personal file portability. **Recommendation:** keep the marketplace (Publish→Browse→Import) and **add** a complementary file `Export`/`Import-from-file` capability (YAML in/out, imported as a draft) — they serve different needs and aren't substitutes.

**Playbook — what does "Run f51985b1 — workflow playbook-58357353-…" mean?**
Both are the **same UUID** surfaced twice. `run_id = uuid4()` and `workflow_id = f"playbook-{run_id}"` (`consumer.py:213-214`). "Run f51985b1" is the first 8 chars of the DB `run_id`; "workflow playbook-58357353-…" is the Temporal workflow id (same UUID, prefixed), used by `/resume` and `/abort` (`main.py:182,206`). FE renders both (`PlaybookDetail.tsx:84-90`), which is why it looks redundant.

**Does VIGIL pull alerts from the SIEM?**
Yes — already the primary ingest path. Interval batch polling (`IngestorEngine._poll_loop`, `services/ingestor/main.py:88-110`) wakes every `splunk_poll_interval_seconds`, pulls SIEM-side notables/incidents/alerts since the last timestamp, normalizes to CDMEvents, and publishes to `vigil.signals.raw`. Connectors: `splunk_es.py:34`, `sentinel.py:197`, `elastic.py:105`. It ingests already-fired SIEM **output**, not raw data. No change needed.

**Evidence Chain vs AI Narrative — which signals live where?**
The Evidence Chain is the authoritative per-signal ledger: `attack.evidence`, one `EvidenceItem` per fired detection, deduped by `signal_id` (`signal_handler.py:172-176,298-315`). The AI Narrative holds **zero discrete signals** — it's Claude-generated prose (`narrative`/`analyst_summary`/`predicted_next_phase`) derived from that same evidence (`ai-engine/prompts/prompts.py:28-40`; `attack-state-engine/main.py:348-390`). "Signals grouped by detection" is a frontend `groupBy(attack.evidence, detection_id)` — no narrative data needed.

---

## 2. Quick wins (shippable this week)

Ordered lowest-effort first.

| Item | Type | Root cause / change | Files | Effort |
|---|---|---|---|---|
| MTTR Trend y-axis shows decimals | ui-polish | `formatDuration` hour/day branches use `.toFixed(1)`; swap to `.toFixed(0)` (ideally only on the axis `tickFormatter`, keep tooltip/headline precise) | `ExecutiveDashboard.tsx:150-183,241-248` | S |
| Attack-by-Phase donut only 2 colors | ui-polish | `fill={i%2===0?ACCENT:ACCENT_DIM}` alternates 2 colors for up to 14 phases. Replace with on-schema red ramp `PALETTE[i%len]`, lifted to a module const | `ExecutiveDashboard.tsx:21-22,107-147`; `tailwind.config.js:6-31` | S |
| Remove "AN-01" (AN-001) in Playbooks | ui-polish | `narrative_id` rendered raw. Either drop the Narrative column/eyebrow, or map `narrative_id`→human name via `listNarratives()` | `PlaybookList.tsx:79,125`; `PlaybookDetail.tsx:82` | S |
| Playbook capitalization inconsistent | ui-polish | `titleCase` missing on `action_type` in `RecommendedActions.tsx:101`; literal "workflow" lowercase | `RecommendedActions.tsx:101`; `PlaybookDetail.tsx:88`; `format.ts:73` | S |
| Cryptic run/workflow label | question/polish | Same UUID twice. Title = narrative name + short run id; move full `workflow_id` to tooltip/copy affordance (keep in model) | `PlaybookDetail.tsx:84-90`; `consumer.py:213-214` | S |
| Drop playbook confidence column (UI part) | architecture/polish | Selector already ignores confidence (`_score_playbook` ignores arg). Hide Confidence column/chip; column can stay in DB | `PlaybookList.tsx:81,128`; `PlaybookDetail.tsx:107`; `narrative_loader.py:117-154` | S→M* |
| Kill Chain: detection counts per phase | feature | Data already client-side: `ps.evidence_ids.length`. Render count badge / proportional bar; pass `attack.evidence` into PhaseTimeline | `PhaseTimeline.tsx:12-67`; `types/attacks.ts:52-61` | S |
| Evidence Chain row clutter | ui-polish | `raw_reference` duplicates `source_siem`. Keep phase+rule_name primary line + compact secondary; move raw_reference/ids to detail | `EvidenceList.tsx:55-62`; `signal_handler.py:309` | S |
| Mark Resolved shows nothing on Resolved page | bug | Shared zustand filter store leaks Active-view phase/confidence/momentum filters into the Resolved query. Give Resolved its own filter namespace (or reset phase/min_confidence/momentum when `resolved=true`); optionally resolve a few in `seed_demo.py` for demo parity | `attackStore.ts:27-58`; `AttackList.tsx:10-37`; `seed_demo.py`; `config.py:46` | M |
| Seeded detection FP rates all 0% | bug | No FP signal in seed data, so aggregation correctly yields `fp_rate=0`. Extend seeders to emit a realistic signal spread + call PATCH `/false-positive` so each detection lands at a plausible, varied FP rate (noisy ~15-25%, high-fidelity ~2-5%) | `performance.py:24-117`; `store.py:333-358`; `scripts/seed_demo.py:109-322` | M |

*The confidence-column hide is S; the full "run 100% of the time" behavioral change is M (see Features — it changes the trigger model, not the selector).

---

## 3. Features

### A. Active Threats — investigation depth & triage

**Triage steps / guided workflow** — *Effort L*
Current: `AttackDetail.tsx` shows status buttons + freeform RecommendedActions only; no ordered checklist. `ResponseStatus` (containment/eradication/recovery booleans+timestamps) exists on the model but only containment is set, and it's never surfaced (`attack_state.py:96-112`; `main.py:303-345`).
Approach: render an ordered, check-offable triage component driven by `ResponseStatus` + `recommended_actions` priority (immediate vs follow_up). Extend the status PATCH (or add an endpoint) to set eradication/recovery the same way containment is set at `main.py:335`. No schema change for v1.
Files: `AttackDetail.tsx:137-214`; `attack_state.py:96-112`; `main.py:303-345`.

**Evidence drill-down (clickable rows)** — *Effort L*
Current: rows are static `<article>` (`EvidenceList.tsx:23-69`). The real blocker is upstream: `_build_evidence` keeps only one primary entity + a flat `raw_reference`, discarding host.ip, description, secondary entities, and `raw_event` that the CDMEvent carries (`signal_handler.py:298-327`; `cdm.py:130-161`). A backend `GET /attacks/{id}/evidence` exists but just re-serializes the thin item and isn't called by the UI (`main.py:282-300`).
Approach: (1) FE expandable/modal detail; (2) **enrich `EvidenceItem`** in `_build_evidence` — carry title/summary, severity, all hosts/ips/users, and a raw_event excerpt. Without (2), a click-through only repeats the 5-6 values already on the row.
Files: `EvidenceList.tsx`; `signal_handler.py:298-327`; `cdm.py:130-161`; `attack_state.py:63-77`.

### B. Lightweight in-transit detection (enabling layer)

**Parse/normalize in transit + extract key fields to alert on** — *Effort M*
Current: `EventNormalizer` already extracts user (with privileged heuristic), host/ip, 5-tuple+bytes, process/parent/hashes/cmdline, file, MITRE, severity, category — but runs on already-fired SIEM notables, and makes no alerting decision (`normalizer.py:70-265`).
Approach: (1) point `EventNormalizer` at raw telemetry (add raw-source field maps; extractors are source-shape tolerant); (2) add a thin CDM-field **predicate/threshold evaluator** (equals/contains/regex/threshold over `process_name`, `parent`, `dst_port`, `is_privileged`). This is the lightweight, reusable seed of the in-transit detection runtime — build it as a CDM rule evaluator, not a SIEM-dialect executor. (Note: two unrelated `normalizer` modules — use ingestor's event→CDM one.)
Files: `normalizer.py:70-265`; `cdm.py`.

**Detections pivot based on what's coming in** — *Effort L (depends on big-bet items)*
Current: adaptive behavior already exists at the **correlation** layer (entity graph + state transitions + confidence accrual, `signal_handler.py:225-420`); detections themselves are static compiled artifacts VIGIL never runs.
Approach: short term, surface/visualize the existing correlation-driven pivoting as "the feature"; medium term, add detection-chaining metadata to YAML (`arms_on: <prior_tactic>`) consumed by the future stream-detection runtime. Truly dynamic version depends on the in-transit detection runtime below.
Files: `signal_handler.py:225-420`; `entity_index.py`; `detections_registry.py`.

### C. Playbook model redesign (deliver as one cohesive workstream)

Items 6–9 below overlap heavily and share a data model; sequence them together.

**Manual + auto trigger / run-from-Actions** — *Effort L*
Current: playbooks start **only** via Kafka on `vigil.attacks.escalated` (confidence>=0.70); no on-demand endpoint (`main.py` has only read + `/resume`/`/abort`); RecommendedActions only ticks complete (`RecommendedActions.tsx:9,85`).
Approach: refactor `consumer._dispatch` body (`select_playbook` + `render_actions_for` + `store.create_run` + temporal start) into a shared function; add `POST /playbooks/run` (or `/attacks/{id}/playbooks`) calling it; add a "Run playbook" button on the Actions UI.
Files: `consumer.py:180-238`; `main.py:168-213`; `RecommendedActions.tsx`.

**Configurable trigger model (auto vs manual)** — *Effort L*
Current: only trigger is the hardcoded escalated subscription; matching is substring of phase/status against a free-text trigger string whose confidence clause is ignored; per-action `automated` flag is metadata only and doesn't gate execution (`narrative_loader.py:117-154`; `response_workflow.py:87-135`).
Approach: add `trigger_mode ∈ {auto, manual}` + structured condition (phase, status, detection_id, min_confidence) replacing the substring match. Auto evaluates the structured condition (optionally subscribe to a detection topic); manual uses the run endpoint above. Reuse `automated` to decide which actions need analyst confirmation.

**"Run 100% of the time" (drop confidence gate)** — *Effort M*
Current: the **gate** is the escalation topic (confidence>=0.70), not the selector (selector already ignores confidence). Approach: change what feeds the consumer — subscribe to a broader topic (`attacks.updated`) or add the manual/auto trigger model above. UI: hide Confidence column/chip (S part above).
Files: `consumer.py:191,201,222`; `attack-state-engine/config.py:22`.

**Build-a-playbook UI** — *Effort XL*
Current: no create/edit UI or endpoint; playbooks are static YAML loaded at startup; only `playbook_runs` table exists (no definitions table) (`App.tsx:54-55`; `narrative_loader.py:71-114`).
Approach (phased): (1) `playbook_definitions` table + CRUD in `main.py`; (2) `narrative_loader` reads DB in addition to YAML so the consumer picks up authored playbooks; (3) frontend builder (pick trigger, select actions from the action library, set priority). Phase as read-only YAML → YAML editor → DB-backed CRUD.

**Edit playbooks + larger action library** — *Effort XL (sub-part A is M)*
Current: 6 fixed actions in `ACTIVITY_DISPATCH` (`response_activities.py:176`); workflow hardcodes per-`action_type` arg-building and treats unknown types as auto-success, so YAML's `search_for_dump_files` is silently skipped (`response_workflow.py:152-185`).
Approach: (A, M) expand the action library + xsoar/tines handlers, and replace the if/elif arg-building (`response_workflow.py:163-177`) with a generic params-dict so adding actions doesn't touch the workflow; close the `search_for_dump_files` gap. (B, XL) edit capability depends on the definitions table + builder above.

**Split playbooks into enrichment vs response** — *Effort L*
Current: no enrichment concept; only priority split (immediate/follow_up); all 6 actions are state-changing response actions (`response_activities.py:162-183`).
Approach: add a `kind` dimension to `PlaybookAction` and the schema — enrichment (read-only, safe to always auto-run) vs response (state-changing, gated/approval). Add enrichment activities (`ioc_lookup`, `asset_context`, `user_context`); workflow runs enrichment first (always) then response (gated). FE: two tabs/sections. This is the spine the rest of the playbook redesign hangs on.

---

## 4. Big bets (architecture)

### Big Bet 1 — Run templated detections on in-transit data (the keystone)
**Today:** VIGIL compiles detections but never runs them — the SIEM does. `signal-translation/compiler.py:106-214` emits SIEM-dialect SPL/KQL/EQL artifacts pushed **to** the customer SIEM; `registry_sync` loads the manifest for governance only. The correlation engine operates on CDMEvents that already carry a `detection_id`. There is no query engine inside VIGIL.
**Build options:**
- (Recommended) A **VIGIL-native predicate format** (field equals/contains/regex/threshold over CDM fields) evaluated in a new stream-detection service consuming a raw-telemetry Kafka topic. Reuses the in-transit normalizer + CDM rule evaluator from Feature B. This is the lightweight, controllable path.
- (Heavier) A stream-processing engine (Flink/ksqlDB/Materialize) — lowest latency, highest ops cost. Compiled SIEM-dialect strings are **not** executable in VIGIL, so this is not a shortcut.
**Integration points:** `EventNormalizer` (reuse as-is), a new raw-telemetry topic, output CDMEvents with `detection_id` flowing into the **existing** correlation pipeline unchanged.
**Sequencing:** build the CDM predicate evaluator (Feature B) first as the MVP; this item is the keystone that Big Bet 2 and the dynamic version of "detections pivot" depend on.

### Big Bet 2 — Real-time ingest as data enters SIEM / S3 / data lake
**Today:** zero streaming/object-store ingest. All four connectors are request/response pollers keyed on a `since` timestamp; "real time" = poll interval, and the polled data is already-detected alerts (`ingestor/main.py:88-110`; `connectors/`). The only event stream is the internal Kafka backbone, which already supports real-time flow (`consumer.py:43-105`).
**Build options:**
- (a) **S3-event-driven micro-batch** (S3→SQS / Firehose on data-lake landing) — cheapest, near-real-time, fits the "data lake" framing.
- (b) **True streaming** (Kafka tap on the customer log bus / Kinesis / Splunk HEC-tap or forwarder fan-out) — lowest latency, higher ops cost.
**Integration points:** new push/streaming connectors → raw-telemetry Kafka topic → detection runtime (Big Bet 1) → existing correlation pipeline. Most new work is at the ingest edge + rule evaluation; the correlation/consumer side is already real-time.
**Sequencing:** write an ADR comparing (a) vs (b); phase S3/SQS data-lake tap first, true streaming later. Depends on Big Bet 1 for the detection runtime.

### Big Bet 3 — AI agents that autonomously find data (agent-less first)
**Today:** 100% agent-less, pull-based. No in-environment agent, no LLM tool-use/data-discovery loop. The only outbound AI is the ai-engine Claude narrator, which summarizes attacks and does **not** query customer data (`ingestor/main.py:37-145`; `ai-engine/narrator.py`).
**Build options:**
- (Recommended first) **Server-side autonomous retrieval (agent-less):** wrap an LLM tool-use loop around the existing connector primitives — give Claude (reuse the ai-engine Anthropic client) tools like `run_splunk_search(spl)`, `query_sentinel(kql)`, `list_cloud_logs()` backed by `ingestor/connectors`, plus a planner driven by an attack hypothesis from attack-state-engine. Keeps code server-side; no customer-host trust burden. **Must inherit the ai-engine budget/breaker spend caps** (per the Claude spend-defenses doc).
- (Defer) **In-environment collection agent (A):** a Go/Python daemon with local read creds that POSTs normalized CDM back. Requires the missing inbound `/signals` endpoint (the SDK's `submit_signal` already assumes it but it 404s today, `main.py:147-192`), agent enrollment/identity, and mTLS — significant deployment/signing/trust burden.
**Integration points:** ai-engine Anthropic client + spend defenses; `ingestor/connectors` as the tool surface; attack-state-engine as the hypothesis source.
**Sequencing:** ship server-side (B) first; defer host agent (A).

### Big Bet 3b — Agent-less detection testing + red-team/attack simulation
**Today:** detection validation is passive/observational — a detection is judged only by whether real telemetry made it fire (`detection_engine_client.py:57-66`; `detection-engine/main.py:364-387`). No Caldera/Atomic/BAS exists. The one seam is `DemoConnector` (`connectors/demo.py:38-161`), a hardcoded 4-step ATT&CK kill-chain (D1 LSASS T1003.001 → D2 dump → D3 reuse T1078 → D4 SMB T1021.002) proving synthetic events flow end-to-end. There is **no inbound `/signals` endpoint** (SDK assumes one; `SIEMMode.HEC` is declared but `_build_connector` never wires a HEC receiver).
**Build options (all agent-less):**
- **Webhook-in:** build the missing `POST /signals` (or HEC-style receiver) on the ingestor that accepts a CDMEvent and publishes straight to `vigil.signals.raw` via `VIGILProducer`. This is the "agent-less equivalent" the roadmap asks about.
- **Detection-test harness:** endpoint that injects a synthetic event for a detection and asserts a row appears via `/internal/signals/record` — turning the passive recorder into an active assertion.
- **Simulation service** (`services/simulation-engine`): generalize `demo.py`'s `_PLAYBOOK` into a YAML scenario library keyed by `technique_id` (reuse `MITREMapping`, `cdm.py:122`); `POST /simulations/run {scenario_id|technique_ids}` emits events; then read back detection records and cross-reference `coverage.py` `uncovered_tactics` to produce a pass/fail purple-team report. Do **not** embed Caldera (it runs real abilities via deployed agents — opposite of agent-less); optionally ingest Caldera/Atomic logs only if a customer already runs them.
**Integration points:** ingestor connector framework + `VIGILProducer` (emit); detection-engine signal recorder + `coverage.py` (validate/score); attack-state-engine (confirm chain assembles).
**Sequencing:** P1 inbound `/signals` webhook + scenario catalog/replay (reuses DemoConnector mechanics); P2 pass/fail coverage report; P3 frontend purple-team view.

---

## 5. Suggested sequencing

**Phase 0 — Quick wins (this week).** All S/M polish and bugs in §2: MTTR decimals, donut palette, AN-001/capitalization/run-label cleanup, Kill-Chain per-phase counts, Evidence row de-clutter, Mark-Resolved filter fix, seeded FP rates. Independent, no dependencies. **Reconcile the SLA Breach Rate double definition** (`aggregator.py:196-222` vs `248-262`) here too — it's small and removes a misleading KPI.

**Phase 1 — Enabling backbone.** Two parallel tracks:
- *Inbound path:* build `POST /signals` webhook receiver on the ingestor (Big Bet 3b P1). This single endpoint unblocks detection-testing, attack simulation, and the future host-agent — and fixes the SDK's 404ing `submit_signal`.
- *Detection primitive:* the in-transit normalizer + CDM predicate evaluator (Feature B). This is the MVP of Big Bet 1's runtime.

**Phase 2 — Playbook model redesign (one cohesive workstream).** Deliver enrichment/response split + definitions table + trigger model + manual run endpoint + expanded action library together (Features C, items 6–9). Start with: shared dispatch refactor + `POST /playbooks/run` (unblocks manual run), then `playbook_definitions` table, then the builder UI. The action-library expansion sub-part (M) can land early and independently.

**Phase 3 — Active Threats depth.** Evidence enrichment (`_build_evidence` model change) + clickable drill-down, and the triage checklist (`ResponseStatus`-driven). The Evidence enrichment is a prerequisite for a meaningful drill-down.

**Phase 4 — Simulation/purple-team.** On top of Phase 1's webhook: scenario catalog → replay → pass/fail coverage report → frontend view (Big Bet 3b P2/P3).

**Phase 5 — Big bets.**
- Big Bet 1 (in-transit detection runtime) builds directly on the Phase 1 predicate evaluator; ADR first.
- Big Bet 2 (real-time S3/stream ingest) feeds Big Bet 1 — ADR comparing S3-micro-batch vs true streaming; ship S3/SQS data-lake tap first.
- Big Bet 3 (autonomous data-finding) — server-side agent-less retrieval reusing the ai-engine Claude client + connector framework, **inheriting the existing spend caps**; defer the in-environment host agent.

**Dependency notes:** Big Bet 1 is the keystone — the dynamic "detections pivot" feature and Big Bet 2 both depend on it. The Phase 1 `/signals` webhook is the shared dependency for detection testing, simulation (Big Bet 3b), and the deferred host agent (Big Bet 3 option A). The playbook redesign items (6–9) should not be shipped piecemeal — they share the `playbook_definitions` schema and trigger model.
