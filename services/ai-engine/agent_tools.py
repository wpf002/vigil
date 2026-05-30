"""Agent-less autonomous retrieval — tool scaffold (Big Bet 3).

See docs/adr/0003-autonomous-agentless-retrieval.md.

This module defines the tool surface for a server-side LLM retrieval loop that,
given an attack hypothesis, pulls supporting telemetry via the existing
connector primitives. It is DELIBERATELY dormant: the live Claude loop is NOT
implemented here and the feature is gated OFF by default, because an
unbounded tool-use cycle is the single highest Claude-spend risk in the product
(see memory/vigil-claude-spend-defenses.md).

Before a live loop is enabled it MUST:
  - run through budget.try_consume() before every Claude call,
  - respect ANTHROPIC_ENABLED + the consecutive-error breaker,
  - enforce MAX_INVESTIGATION_STEPS and a per-investigation token ceiling.
"""

from __future__ import annotations

import os
from typing import Any

# Hard gate. The loop never runs until this is explicitly turned on per-tenant
# after the step/token caps are load-tested.
RETRIEVAL_ENABLED_ENV = "AGENT_RETRIEVAL_ENABLED"
MAX_INVESTIGATION_STEPS = int(os.getenv("AGENT_MAX_STEPS", "6"))


def retrieval_enabled() -> bool:
    return os.getenv(RETRIEVAL_ENABLED_ENV, "false").lower() == "true"


# Anthropic tool-use schemas. Backed by ingestor/connectors when wired.
TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "name": "run_splunk_search",
        "description": "Run a read-only SPL search against the customer's Splunk and return matching events.",
        "input_schema": {
            "type": "object",
            "properties": {
                "spl": {"type": "string", "description": "SPL query (read-only)"},
                "earliest": {"type": "string", "description": "e.g. -24h"},
            },
            "required": ["spl"],
        },
    },
    {
        "name": "query_sentinel",
        "description": "Run a read-only KQL query against Microsoft Sentinel and return rows.",
        "input_schema": {
            "type": "object",
            "properties": {"kql": {"type": "string"}},
            "required": ["kql"],
        },
    },
    {
        "name": "list_cloud_logs",
        "description": "List available cloud log sources/streams for the tenant.",
        "input_schema": {"type": "object", "properties": {}},
    },
]

SYSTEM_PROMPT = (
    "You are a SOC investigator. Given an attack hypothesis, use the provided "
    "read-only tools to gather supporting or refuting telemetry. Never modify "
    "state. Stop as soon as the hypothesis is confirmed or refuted, or when you "
    f"have used {MAX_INVESTIGATION_STEPS} tool calls."
)


def build_plan(hypothesis: str) -> dict[str, Any]:
    """Return the prompt + tool surface for an investigation. Pure — performs NO
    Claude call. The live loop (gated, budget-guarded) is intentionally not
    implemented here yet."""
    return {
        "system": SYSTEM_PROMPT,
        "user": f"Attack hypothesis to investigate: {hypothesis}",
        "tools": TOOL_SCHEMAS,
        "max_steps": MAX_INVESTIGATION_STEPS,
        "enabled": retrieval_enabled(),
    }
