"""Agent-less autonomous retrieval (Big Bet 3).

See docs/adr/0003-autonomous-agentless-retrieval.md.

A server-side LLM tool-use loop that, given an attack hypothesis, pulls
supporting telemetry via tool calls. Because an unbounded tool-use cycle is the
single highest Claude-spend risk in the product (see
memory/vigil-claude-spend-defenses.md), the loop inherits EVERY ai-engine
defense and adds two of its own:

  1. Hard gate — AGENT_RETRIEVAL_ENABLED (off by default) AND the global
     ANTHROPIC_ENABLED kill switch. Either off → no Claude call, ever.
  2. Shared daily budget — budget.try_consume() runs BEFORE every Claude call;
     the cap is shared with the narrator and fails closed if Redis is down.
  3. Step cap — at most AGENT_MAX_STEPS tool-use iterations per investigation.
  4. Token ceiling — stop once AGENT_TOKEN_CEILING tokens are spent.
  5. Per-call max_tokens cap + max_retries=0 (inherited from the shared client).
  6. Consecutive-error breaker — bail after 3 errors in a row.
"""

from __future__ import annotations

import asyncio
import os
from typing import Any, Callable, Optional

import structlog

logger = structlog.get_logger(__name__)

RETRIEVAL_ENABLED_ENV = "AGENT_RETRIEVAL_ENABLED"
MAX_INVESTIGATION_STEPS = int(os.getenv("AGENT_MAX_STEPS", "6"))
TOKEN_CEILING = int(os.getenv("AGENT_TOKEN_CEILING", "30000"))
MAX_TOKENS_PER_CALL = int(os.getenv("AGENT_MAX_TOKENS_PER_CALL", "1024"))
_ERROR_BREAKER = 3


def retrieval_enabled() -> bool:
    return os.getenv(RETRIEVAL_ENABLED_ENV, "false").lower() == "true"


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
    f"have used {MAX_INVESTIGATION_STEPS} tool calls, and give a short verdict."
)


def build_plan(hypothesis: str) -> dict[str, Any]:
    """Prompt + tool surface for an investigation. Pure — no Claude call."""
    return {
        "system": SYSTEM_PROMPT,
        "user": f"Attack hypothesis to investigate: {hypothesis}",
        "tools": TOOL_SCHEMAS,
        "max_steps": MAX_INVESTIGATION_STEPS,
        "enabled": retrieval_enabled(),
    }


# ── tool handlers ─────────────────────────────────────────────────────────────
# Default handlers return clearly-labelled stub telemetry so the loop is fully
# exercisable without live SIEM credentials. Replace with ingestor/connectors
# (ADR 0003) to make retrieval real. handler(tool_input, tenant_id) -> str.
ToolHandler = Callable[[dict[str, Any], str], str]


def _stub_splunk(inp: dict[str, Any], tenant_id: str) -> str:
    return (f"[stub] SPL `{inp.get('spl', '')}` ({inp.get('earliest', '-24h')}): "
            "3 events — host=SRV-FILE-01 user=svc_backup action=lsass_access; "
            "host=WORKSTATION-12 process=rundll32.exe. "
            "(connect a real Splunk connector to replace this stub)")


def _stub_sentinel(inp: dict[str, Any], tenant_id: str) -> str:
    return (f"[stub] KQL `{inp.get('kql', '')}`: 1 row — "
            "SigninLogs: impossible-travel for user jdoe (NY→SG, 4m apart).")


def _stub_cloud_logs(inp: dict[str, Any], tenant_id: str) -> str:
    return "[stub] cloud log sources: aws.cloudtrail, gcp.audit, azure.signin"


DEFAULT_TOOL_HANDLERS: dict[str, ToolHandler] = {
    "run_splunk_search": _stub_splunk,
    "query_sentinel": _stub_sentinel,
    "list_cloud_logs": _stub_cloud_logs,
}


def _block_attr(block: Any, name: str, default: Any = None) -> Any:
    if isinstance(block, dict):
        return block.get(name, default)
    return getattr(block, name, default)


async def run_investigation(
    *,
    hypothesis: str,
    tenant_id: str,
    client: Any,
    model: str,
    budget: Any,
    narrator_enabled: bool,
    tool_handlers: Optional[dict[str, ToolHandler]] = None,
    max_steps: int = MAX_INVESTIGATION_STEPS,
) -> dict[str, Any]:
    """Run the bounded tool-use investigation loop. Returns a transcript.

    Performs ZERO Claude calls when disabled or kill-switched, and never exceeds
    the daily budget, step cap, or token ceiling.
    """
    if not retrieval_enabled():
        return {"enabled": False, "reason": "AGENT_RETRIEVAL_ENABLED is off",
                "steps": 0, "tokens": 0, "transcript": []}
    if not narrator_enabled:
        return {"enabled": False, "reason": "ANTHROPIC_ENABLED kill switch is off",
                "steps": 0, "tokens": 0, "transcript": []}

    handlers = tool_handlers or DEFAULT_TOOL_HANDLERS
    messages: list[dict[str, Any]] = [
        {"role": "user", "content": f"Attack hypothesis: {hypothesis}"}
    ]
    transcript: list[dict[str, Any]] = []
    total_tokens = 0
    steps = 0
    errors = 0
    loop = asyncio.get_event_loop()

    while steps < max_steps:
        # Budget gate BEFORE every Claude call — shared cap, fails closed.
        allowed, count = await budget.try_consume()
        if not allowed:
            transcript.append({"event": "budget_exhausted", "count": count})
            return {"enabled": True, "final": None, "steps": steps,
                    "tokens": total_tokens, "stopped": "budget", "transcript": transcript}
        if total_tokens >= TOKEN_CEILING:
            transcript.append({"event": "token_ceiling", "tokens": total_tokens})
            return {"enabled": True, "final": None, "steps": steps,
                    "tokens": total_tokens, "stopped": "token_ceiling", "transcript": transcript}

        steps += 1
        try:
            resp = await loop.run_in_executor(
                None,
                lambda: client.messages.create(
                    model=model, max_tokens=MAX_TOKENS_PER_CALL,
                    system=SYSTEM_PROMPT, tools=TOOL_SCHEMAS, messages=messages,
                ),
            )
            errors = 0
        except Exception as e:  # noqa: BLE001
            errors += 1
            transcript.append({"event": "error", "error": str(e)})
            if errors >= _ERROR_BREAKER:
                return {"enabled": True, "final": None, "steps": steps,
                        "tokens": total_tokens, "stopped": "error_breaker", "transcript": transcript}
            continue

        usage = getattr(resp, "usage", None)
        if usage is not None:
            total_tokens += int(getattr(usage, "input_tokens", 0) or 0)
            total_tokens += int(getattr(usage, "output_tokens", 0) or 0)

        content = resp.content
        messages.append({"role": "assistant", "content": content})
        tool_uses = [b for b in content if _block_attr(b, "type") == "tool_use"]

        if not tool_uses:
            final = " ".join(
                _block_attr(b, "text", "") for b in content if _block_attr(b, "type") == "text"
            ).strip()
            transcript.append({"event": "final", "text": final})
            return {"enabled": True, "final": final, "steps": steps,
                    "tokens": total_tokens, "stopped": "answered", "transcript": transcript}

        tool_results = []
        for tu in tool_uses:
            name = _block_attr(tu, "name")
            tinput = _block_attr(tu, "input", {}) or {}
            handler = handlers.get(name)
            result = handler(tinput, tenant_id) if handler else f"unknown tool: {name}"
            transcript.append({"event": "tool", "name": name, "input": tinput,
                               "result_preview": str(result)[:200]})
            tool_results.append({"type": "tool_result", "tool_use_id": _block_attr(tu, "id"),
                                 "content": str(result)})
        messages.append({"role": "user", "content": tool_results})

    return {"enabled": True, "final": None, "steps": steps, "tokens": total_tokens,
            "stopped": "max_steps", "transcript": transcript}
