"""Tests for the AI engine narrator.

No live Anthropic calls. The Anthropic client is mocked end-to-end so we
can assert the request shape (system block uses cache_control: ephemeral),
parse-error tolerance, and the output schema.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock

import pytest

from ai_engine.narrator import (
    SYSTEM_PROMPT,
    CircuitOpen,
    NarrativeResult,
    Narrator,
    parse_response_text,
)

# ── helpers ─────────────────────────────────────────────────────────────────

def _state(confidence: float = 0.65) -> dict[str, Any]:
    return {
        "attack_id": "11111111-1111-1111-1111-111111111111",
        "name": "Credential Access on DC-PRIMARY",
        "current_phase": "credential-access",
        "status": "active",
        "confidence": confidence,
        "momentum": "Increasing",
        "impact": "High",
        "phases": [
            {"phase": "credential-access", "status": "Confirmed",
             "first_seen": "2024-01-01T00:00:00Z", "last_seen": "2024-01-01T00:05:00Z"}
        ],
        "users": ["svc_backup"],
        "hosts": ["DC-PRIMARY"],
        "evidence": [
            {"signal_id": "s1", "phase": "credential-access",
             "timestamp": "2024-01-01T00:00:00Z",
             "status_contributed": "Observed", "confidence_contribution": 0.25,
             "source_siem": "splunk_es", "entity_type": "host",
             "entity_value": "DC-PRIMARY"},
        ],
        "recommended_actions": [],
        "first_seen": "2024-01-01T00:00:00Z",
        "last_seen": "2024-01-01T00:05:00Z",
    }


def _mock_client_returning(text: str) -> MagicMock:
    client = MagicMock()
    msg = MagicMock()

    block = MagicMock()
    block.type = "text"
    block.text = text
    msg.content = [block]

    client.messages.create.return_value = msg
    return client


# ── parse tests ─────────────────────────────────────────────────────────────

def test_parse_minimal_response():
    raw = json.dumps({
        "narrative": "Attacker accessed LSASS on DC-PRIMARY at 00:00, "
                     "then dumped credentials, then moved laterally.",
        "predicted_next_phase": "lateral-movement",
        "analyst_summary": "Isolate DC-PRIMARY immediately.",
        "confidence_note": None,
    })
    result = parse_response_text(raw)
    assert result.predicted_next_phase == "lateral-movement"
    assert result.confidence_note is None
    assert "DC-PRIMARY" in result.narrative


def test_parse_with_code_fences():
    raw = "```json\n" + json.dumps({
        "narrative": "x", "predicted_next_phase": None,
        "analyst_summary": "y", "confidence_note": None,
    }) + "\n```"
    result = parse_response_text(raw)
    assert result.narrative == "x"
    assert result.analyst_summary == "y"


def test_parse_drops_invalid_predicted_phase():
    raw = json.dumps({
        "narrative": "x",
        "predicted_next_phase": "made-up-phase",
        "analyst_summary": "y",
        "confidence_note": None,
    })
    result = parse_response_text(raw)
    assert result.predicted_next_phase is None


def test_parse_missing_narrative_raises():
    raw = json.dumps({
        "predicted_next_phase": None,
        "analyst_summary": "y",
        "confidence_note": None,
    })
    with pytest.raises(ValueError):
        parse_response_text(raw)


def test_parse_with_trailing_prose():
    raw = "Here is the JSON:\n" + json.dumps({
        "narrative": "x",
        "predicted_next_phase": None,
        "analyst_summary": "y",
        "confidence_note": None,
    }) + "\nThanks."
    result = parse_response_text(raw)
    assert result.narrative == "x"


# ── narrator tests ──────────────────────────────────────────────────────────

def test_narrator_returns_parsed_result():
    client = _mock_client_returning(json.dumps({
        "narrative": "Three-line summary.",
        "predicted_next_phase": "lateral-movement",
        "analyst_summary": "Isolate the host now.",
        "confidence_note": None,
    }))
    narrator = Narrator(client=client, model="claude-sonnet-4-6")
    result = narrator.generate(_state(confidence=0.65))
    assert isinstance(result, NarrativeResult)
    assert result.predicted_next_phase == "lateral-movement"


def test_narrator_request_shape():
    """Lock down the request shape: system prompt is set, no extra params
    that the SDK would reject. (Earlier code passed output_config={effort:low}
    — not a real Anthropic param — and every call 400'd.)
    """
    client = _mock_client_returning(json.dumps({
        "narrative": "x", "predicted_next_phase": None,
        "analyst_summary": "y", "confidence_note": None,
    }))
    narrator = Narrator(client=client, model="claude-sonnet-4-6")
    narrator.generate(_state())

    kwargs = client.messages.create.call_args.kwargs
    assert kwargs["system"] == SYSTEM_PROMPT
    assert kwargs["model"] == "claude-sonnet-4-6"
    assert kwargs["max_tokens"] == 1024
    assert "output_config" not in kwargs


def test_narrator_disabled_returns_stub_without_calling_client():
    """Soft kill switch — no Claude call when enabled=False."""
    client = MagicMock()
    narrator = Narrator(client=client, model="claude-sonnet-4-6", enabled=False)
    result = narrator.generate(_state())
    assert isinstance(result, NarrativeResult)
    assert "paused" in result.narrative.lower()
    client.messages.create.assert_not_called()


def test_circuit_breaker_trips_after_n_errors():
    """After N consecutive errors, the breaker opens and further calls raise
    CircuitOpen without ever touching the Anthropic client.
    """
    client = MagicMock()
    client.messages.create.side_effect = RuntimeError("boom")
    narrator = Narrator(
        client=client, model="claude-sonnet-4-6", consecutive_error_limit=3
    )

    for _ in range(3):
        with pytest.raises(RuntimeError):
            narrator.generate(_state())

    assert narrator.circuit_open is True
    # Next call must NOT hit the client.
    client.messages.create.reset_mock()
    with pytest.raises(CircuitOpen):
        narrator.generate(_state())
    client.messages.create.assert_not_called()


def test_circuit_breaker_resets_on_success():
    """One good call clears the consecutive-error counter."""
    client = MagicMock()
    good = MagicMock()
    good_block = MagicMock()
    good_block.type = "text"
    good_block.text = json.dumps({
        "narrative": "x", "predicted_next_phase": None,
        "analyst_summary": "y", "confidence_note": None,
    })
    good.content = [good_block]

    client.messages.create.side_effect = [
        RuntimeError("boom"),
        RuntimeError("boom"),
        good,
    ]
    narrator = Narrator(
        client=client, model="claude-sonnet-4-6", consecutive_error_limit=3
    )

    for _ in range(2):
        with pytest.raises(RuntimeError):
            narrator.generate(_state())
    assert narrator.consecutive_errors == 2

    narrator.generate(_state())
    assert narrator.consecutive_errors == 0
    assert narrator.circuit_open is False


def test_force_disable_and_enable():
    client = MagicMock()
    narrator = Narrator(client=client, model="claude-sonnet-4-6")
    narrator.force_disable()
    narrator.generate(_state())
    client.messages.create.assert_not_called()

    narrator.force_enable()
    # Enabling resets the breaker too.
    assert narrator.circuit_open is False
    assert narrator.consecutive_errors == 0


def test_narrator_truncates_evidence_to_20():
    """Long evidence chains must be trimmed before sending."""
    client = _mock_client_returning(json.dumps({
        "narrative": "x", "predicted_next_phase": None,
        "analyst_summary": "y", "confidence_note": None,
    }))
    narrator = Narrator(client=client, model="claude-sonnet-4-6")

    state = _state()
    state["evidence"] = [
        {"signal_id": f"s{i}", "phase": "credential-access",
         "timestamp": f"2024-01-01T00:{i:02d}:00Z",
         "status_contributed": "Observed", "confidence_contribution": 0.1,
         "source_siem": "splunk", "entity_type": "host",
         "entity_value": "h"}
        for i in range(30)
    ]
    narrator.generate(state)

    user_msg = client.messages.create.call_args.kwargs["messages"][0]["content"]
    # Confirm only the last 20 evidence items by signal_id are present.
    assert "s29" in user_msg
    assert "s10" in user_msg
    assert "s9" not in user_msg


def test_narrator_propagates_api_error():
    client = MagicMock()
    client.messages.create.side_effect = RuntimeError("503 Service Unavailable")
    narrator = Narrator(client=client, model="claude-sonnet-4-6")
    with pytest.raises(RuntimeError):
        narrator.generate(_state())


def test_confidence_note_required_for_low_confidence_only():
    """The model is *instructed* to set confidence_note when < 0.50.
    The narrator must accept None when >= 0.50 — verified above. Here we
    confirm a non-null note is preserved through parsing.
    """
    raw = json.dumps({
        "narrative": "x",
        "predicted_next_phase": None,
        "analyst_summary": "y",
        "confidence_note": "Need a successful auth event from a non-admin account "
                           "to elevate from Observed to Confirmed.",
    })
    result = parse_response_text(raw)
    assert result.confidence_note is not None
    assert "Confirmed" in result.confidence_note


# ── patch body shape ────────────────────────────────────────────────────────

def test_to_patch_body_shape():
    result = NarrativeResult(
        narrative="x",
        predicted_next_phase="lateral-movement",
        analyst_summary="y",
        confidence_note=None,
    )
    body = result.to_patch_body()
    assert set(body.keys()) == {
        "narrative", "predicted_next_phase", "analyst_summary", "confidence_note"
    }
