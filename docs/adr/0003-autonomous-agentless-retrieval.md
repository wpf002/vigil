# ADR 0003 — AI agents that autonomously find data (Big Bet 3)

Status: Accepted (design + gated scaffold) · Date: 2026-05-30

## Context

VIGIL is 100% agent-less and pull-based. The only outbound AI is the ai-engine
Claude narrator, which summarizes attacks and does **not** query customer data.
We want an agent that, given an attack hypothesis, autonomously pulls the
supporting telemetry.

## Decision

**Server-side, agent-less retrieval first.** Wrap an LLM tool-use loop around the
existing connector primitives — Claude (reuse the ai-engine Anthropic client)
gets tools like `run_splunk_search`, `query_sentinel`, `list_cloud_logs` backed
by `ingestor/connectors`, plus a planner seeded by an attack hypothesis from
attack-state-engine. No in-environment agent, no host trust burden.

**Defer** the in-environment collection agent (a daemon with local read creds):
it needs the inbound `/signals` path (now shipped), agent enrollment/identity,
and mTLS — significant deployment/signing/trust burden for later.

## Spend safety (hard requirement)

This loop calls Claude in a cycle, so it is the single highest spend risk in the
product. It **must** inherit the existing ai-engine defenses (see
`memory/vigil-claude-spend-defenses.md`):
- the hard daily Redis budget (`ANTHROPIC_DAILY_CALL_BUDGET`, fail-closed),
- the soft kill switch (`ANTHROPIC_ENABLED`),
- the consecutive-error breaker, and `max_retries=0`,
- plus a **per-investigation step cap** (max tool-call iterations) and a
  per-investigation token ceiling.

Because of this, the live loop ships **disabled by default**. The scaffold in
this repo (`services/ai-engine/agent_tools.py`) defines the tool schemas and the
connector-backed handlers but is gated behind `AGENT_RETRIEVAL_ENABLED=false`
and routed through `budget.try_consume()` before any Claude call. It is not
enabled in any environment until the step/token caps are load-tested.

## Options considered

1. **Server-side agent-less retrieval (chosen).** Code stays server-side;
   reuses connectors as the tool surface; inherits spend caps.
2. **In-environment host agent.** Deferred — trust/deployment burden.

## Consequences

- Tool surface = `ingestor/connectors`; hypothesis source = attack-state-engine;
  brain = ai-engine Anthropic client under the spend defenses.
- Until the live loop is enabled, the scaffold is dormant — zero spend.

## Sequencing

Tool schemas + gated scaffold (this ADR) → step/token caps + dry-run harness →
enable behind the budget on a single tenant → expand.
