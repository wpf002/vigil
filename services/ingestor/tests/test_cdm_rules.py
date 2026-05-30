"""Tests for the in-transit CDM predicate evaluator."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from ..cdm_rules import (
    DEFAULT_RULES,
    CDMRule,
    Condition,
    apply_match,
    best_match,
    eval_condition,
    evaluate,
    resolve_field,
)
from ..models.cdm import CDMEvent, ProcessEntity


def _event(**process) -> CDMEvent:
    return CDMEvent(
        tenant_id="t",
        source_event_id="e1",
        timestamp=datetime.now(timezone.utc),
        title="raw telemetry",
        process=ProcessEntity(**process) if process else None,
    )


# ── ops ────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("actual,op,target,expected", [
    ("powershell.exe", "contains", "powershell", True),
    ("CMD.EXE", "equals", "cmd.exe", True),          # case-insensitive
    (445, "equals", 445, True),
    (445, "gt", 1024, False),
    (8080, "gte", 8080, True),
    (True, "equals", True, True),
    (None, "exists", None, False),
    ("x", "exists", None, True),
    ("net1 user /domain", "regex", r"net1?\s+user.*/domain", True),
    ("admin", "in", ["root", "admin"], True),
    ("nope", "in", ["root", "admin"], False),
    (None, "equals", "x", False),
])
def test_eval_condition(actual, op, target, expected):
    assert eval_condition(actual, op, target) is expected


def test_resolve_field_dotted_path():
    d = _event(process_name="x.exe").model_dump(mode="json")
    assert resolve_field(d, "process.process_name") == "x.exe"
    assert resolve_field(d, "process.missing") is None
    assert resolve_field(d, "network.dst_port") is None  # network is None


# ── rule matching ──────────────────────────────────────────────────────────
def test_encoded_powershell_matches():
    ev = _event(process_name="powershell.exe",
                command_line="powershell -EncodedCommand SQBFAFgA")
    m = best_match(ev, DEFAULT_RULES)
    assert m is not None and m.detection_id == "D5-POWERSHELL-ENCODED-COMMAND"


def test_fodhelper_matches_and_apply():
    ev = _event(process_name="fodhelper.exe")
    rule = best_match(ev, DEFAULT_RULES)
    assert rule and rule.detection_id == "D7-UAC-BYPASS-FODHELPER"
    apply_match(ev, rule)
    assert ev.detection_id == "D7-UAC-BYPASS-FODHELPER"
    assert ev.state_impact["phase"] == "privilege-escalation"
    assert ev.state_impact["confidence_contribution"] == rule.confidence


def test_and_semantics_no_partial_match():
    # sc.exe WITHOUT "create" must not fire the new-service rule
    ev = _event(process_name="sc.exe", command_line="sc.exe query")
    assert all(r.detection_id != "D6-NEW-SERVICE-INSTALL" for r in evaluate(ev, DEFAULT_RULES))
    ev2 = _event(process_name="sc.exe", command_line="sc.exe create evil binpath=...")
    assert any(r.detection_id == "D6-NEW-SERVICE-INSTALL" for r in evaluate(ev2, DEFAULT_RULES))


def test_benign_event_matches_nothing():
    ev = _event(process_name="explorer.exe", command_line="explorer.exe")
    assert evaluate(ev, DEFAULT_RULES) == []
    assert best_match(ev, DEFAULT_RULES) is None


def test_best_match_picks_highest_confidence():
    # lsass + fodhelper both present -> fodhelper (0.85) beats lsass (0.75)
    ev = _event(process_name="fodhelper.exe", command_line="dump lsass.exe")
    assert best_match(ev, DEFAULT_RULES).detection_id == "D7-UAC-BYPASS-FODHELPER"


def test_custom_rule():
    ev = _event(process_name="rundll32.exe")
    rule = CDMRule(detection_id="X", name="r", conditions=[
        Condition("process.process_name", "equals", "rundll32.exe")])
    assert best_match(ev, [rule]).detection_id == "X"
