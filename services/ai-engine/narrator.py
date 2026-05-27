"""Anthropic-backed narrative generator.

Reasons over a JSON-serialized AttackState; returns structured narrative
fields suitable for PATCHing back to attack-state-engine.

Spend defenses (layered, fail-closed):
  1. ``enabled`` flag (env kill switch) — softest gate, short-circuits to stub.
  2. Async ``budget`` (Redis-backed, atomic) — hard daily cap, checked by
     callers via ``budget.try_consume()`` BEFORE invoking ``generate()``.
  3. In-process consecutive-error breaker — after N errors this replica
     refuses to call Claude until restart, so an auth/quota fault can't
     drive a 30-second-poll-forever billing loop.
  4. ``max_retries=0`` on the Anthropic client (set in main.py) — the SDK
     retries 2x by default, which silently triples cost on transient errors.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Optional

import structlog

logger = structlog.get_logger(__name__)


SYSTEM_PROMPT = (
    "You are VIGIL's attack analysis engine. You reason over live "
    "AttackState objects — structured representations of adversary "
    "activity observed in a customer environment. Be specific about "
    "entities, timestamps, and techniques. Separate CONFIRMED from "
    "INFERRED. Never recommend actions you cannot justify from the "
    "evidence. If confidence is below 0.50, say so and explain what "
    "would confirm the threat."
)


@dataclass
class NarrativeResult:
    narrative: str
    predicted_next_phase: Optional[str]
    analyst_summary: str
    confidence_note: Optional[str]

    def to_patch_body(self) -> dict[str, Any]:
        return {
            "narrative": self.narrative,
            "predicted_next_phase": self.predicted_next_phase,
            "analyst_summary": self.analyst_summary,
            "confidence_note": self.confidence_note,
        }


_VALID_TACTICS = {
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
}


def _trim_attack_state(state: dict[str, Any]) -> dict[str, Any]:
    """Shrink the AttackState payload sent to the model.

    The full evidence chain can be long; the spec says oldest-20 only.
    Other large lists left intact — they're typically small.
    """
    evidence = state.get("evidence") or []
    try:
        evidence_sorted = sorted(evidence, key=lambda e: e.get("timestamp") or "")
    except TypeError:
        evidence_sorted = evidence
    trimmed_evidence = evidence_sorted[-20:]

    return {
        "attack_id": state.get("attack_id"),
        "name": state.get("name"),
        "current_phase": state.get("current_phase"),
        "status": state.get("status"),
        "confidence": state.get("confidence"),
        "momentum": state.get("momentum"),
        "impact": state.get("impact"),
        "phases_observed": state.get("phases") or [],
        "users": state.get("users") or [],
        "hosts": state.get("hosts") or [],
        "processes": state.get("processes") or [],
        "credentials": state.get("credentials") or [],
        "evidence": trimmed_evidence,
        "recommended_actions": state.get("recommended_actions") or [],
        "first_seen": state.get("first_seen"),
        "last_seen": state.get("last_seen"),
    }


def _build_user_message(state: dict[str, Any]) -> str:
    payload = _trim_attack_state(state)
    return (
        "Analyze the following AttackState and return JSON with EXACTLY these "
        "keys (no preamble, no markdown fences):\n"
        '  - "narrative": 3-5 sentence plain-English summary\n'
        '  - "predicted_next_phase": one of the MITRE tactic strings, or null\n'
        '  - "analyst_summary": 1-2 sentence statement of what the analyst must do now\n'
        '  - "confidence_note": null if confidence >= 0.50, otherwise a short '
        "explanation of what would confirm the threat\n\n"
        f"AttackState:\n{json.dumps(payload, default=str, indent=2)}"
    )


def _strip_code_fences(text: str) -> str:
    s = text.strip()
    if s.startswith("```"):
        first_newline = s.find("\n")
        if first_newline != -1:
            s = s[first_newline + 1 :]
        if s.endswith("```"):
            s = s[: -3]
    return s.strip()


def parse_response_text(text: str) -> NarrativeResult:
    """Parse the model's textual response into a NarrativeResult."""
    cleaned = _strip_code_fences(text)
    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError:
        start = cleaned.find("{")
        end = cleaned.rfind("}")
        if start == -1 or end == -1 or end <= start:
            raise ValueError(f"Cannot parse JSON from response: {cleaned[:200]!r}")
        data = json.loads(cleaned[start : end + 1])

    narrative = str(data.get("narrative") or "").strip()
    if not narrative:
        raise ValueError("Response missing 'narrative'")

    predicted = data.get("predicted_next_phase")
    if predicted is not None:
        predicted = str(predicted)
        if predicted not in _VALID_TACTICS:
            predicted = None

    analyst_summary = str(data.get("analyst_summary") or "").strip()
    if not analyst_summary:
        raise ValueError("Response missing 'analyst_summary'")

    confidence_note = data.get("confidence_note")
    if confidence_note is not None:
        confidence_note = str(confidence_note).strip() or None

    return NarrativeResult(
        narrative=narrative,
        predicted_next_phase=predicted,
        analyst_summary=analyst_summary,
        confidence_note=confidence_note,
    )


def _stub_result(state: dict[str, Any], reason: str = "disabled") -> NarrativeResult:
    """Deterministic placeholder. ``reason`` is surfaced to operators so they
    can tell a kill-switch stub apart from a budget-exhausted stub apart from
    a circuit-open stub.
    """
    phase = state.get("current_phase") or "unknown"
    confidence = state.get("confidence") or 0.0
    return NarrativeResult(
        narrative=(
            f"Narrative generation is paused ({reason}). "
            f"Attack is at phase '{phase}' with confidence {confidence:.2f}."
        ),
        predicted_next_phase=None,
        analyst_summary=f"Re-enable the AI engine ({reason}) to get a model-generated summary.",
        confidence_note=None,
    )


class CircuitOpen(Exception):
    """Raised when the in-process error breaker has tripped."""


class Narrator:
    """Wraps an Anthropic client. Tests pass a mock client.

    The narrator owns its in-process circuit breaker. The async, cross-replica
    daily budget lives in ``budget.py`` and is enforced by callers before they
    invoke ``generate()`` (so the budget check can stay async without forcing
    every caller through the synchronous SDK code path).
    """

    def __init__(
        self,
        client,
        model: str,
        enabled: bool = True,
        consecutive_error_limit: int = 5,
    ):
        self._client = client
        self._model = model
        self._enabled = enabled
        self._error_limit = max(consecutive_error_limit, 1)
        self._consecutive_errors = 0
        self._circuit_open = False

    @property
    def circuit_open(self) -> bool:
        return self._circuit_open

    @property
    def consecutive_errors(self) -> int:
        return self._consecutive_errors

    def force_disable(self) -> None:
        """Runtime kill switch — called by the admin endpoint."""
        self._enabled = False

    def force_enable(self) -> None:
        """Re-enable after operator review. Resets the breaker too."""
        self._enabled = True
        self._circuit_open = False
        self._consecutive_errors = 0

    def generate(self, state: dict[str, Any]) -> NarrativeResult:
        """Synchronous call (Anthropic Python SDK is sync). Caller may
        offload to a thread pool if it needs concurrency.

        Returns a stub (no API call) when disabled. Raises CircuitOpen
        (no API call) when too many consecutive errors have tripped this
        replica's breaker; the caller logs and moves on.
        """
        if not self._enabled:
            logger.info("ai_engine.narrator.disabled_stub_returned",
                        attack_id=state.get("attack_id"))
            return _stub_result(state, reason="kill switch on")

        if self._circuit_open:
            logger.warning(
                "ai_engine.narrator.circuit_open_skipping_claude",
                attack_id=state.get("attack_id"),
                consecutive_errors=self._consecutive_errors,
            )
            raise CircuitOpen(
                f"breaker tripped after {self._consecutive_errors} consecutive errors"
            )

        try:
            message = self._client.messages.create(
                model=self._model,
                max_tokens=1024,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": _build_user_message(state)}],
            )
        except Exception:
            self._consecutive_errors += 1
            if self._consecutive_errors >= self._error_limit:
                self._circuit_open = True
                logger.error(
                    "ai_engine.narrator.circuit_tripped",
                    consecutive_errors=self._consecutive_errors,
                    limit=self._error_limit,
                    hint="narrator disabled in this replica until restart",
                )
            raise

        # Reset the breaker on any successful call.
        self._consecutive_errors = 0
        text = _extract_text(message)
        return parse_response_text(text)


def _extract_text(message: Any) -> str:
    content = getattr(message, "content", None)
    if content is None and isinstance(message, dict):
        content = message.get("content")
    if not content:
        raise ValueError("Empty response from Anthropic")

    parts: list[str] = []
    for block in content:
        block_type = getattr(block, "type", None) or (block.get("type") if isinstance(block, dict) else None)
        if block_type == "text":
            text = getattr(block, "text", None) or (block.get("text") if isinstance(block, dict) else None)
            if text:
                parts.append(text)
    if not parts:
        raise ValueError("No text block in response")
    return "\n".join(parts)
