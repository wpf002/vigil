"""Tests for authored playbook definitions → runnable Playbook + selection."""

from __future__ import annotations

from playbook_engine.narrative_loader import (
    Narrative,
    playbook_from_definition,
    select_playbook,
)


def test_definition_splits_actions_by_kind_and_priority():
    d = {
        "name": "Custom CredAccess",
        "trigger_mode": "manual",
        "trigger_phase": "credential-access",
        "trigger_status": None,
        "min_confidence": 0.0,
        "trigger_detection_id": None,
        "actions": [
            {"action_type": "asset_context", "target": "affected_host", "kind": "enrichment", "priority": "immediate"},
            {"action_type": "isolate_host", "target": "affected_host", "kind": "response", "priority": "immediate"},
            {"action_type": "reset_credentials", "target": "affected_user", "kind": "response", "priority": "follow_up"},
        ],
    }
    pb = playbook_from_definition(d)
    assert pb.trigger_mode == "manual"
    assert pb.trigger_phase == "credential-access"
    assert [a.action_type for a in pb.enrichment] == ["asset_context"]
    assert [a.action_type for a in pb.immediate] == ["isolate_host"]
    assert [a.action_type for a in pb.follow_up] == ["reset_credentials"]


def test_definition_infers_kind_when_omitted():
    d = {"name": "x", "trigger_phase": "execution",
         "actions": [{"action_type": "ioc_lookup", "target": "x"}]}
    pb = playbook_from_definition(d)
    assert [a.action_type for a in pb.enrichment] == ["ioc_lookup"]


def test_db_definition_is_selectable_and_respects_trigger():
    d = {"name": "Custom Impact", "trigger_mode": "auto", "trigger_phase": "impact",
         "min_confidence": 0.5,
         "actions": [{"action_type": "isolate_host", "target": "h"}]}
    pb = playbook_from_definition(d)
    ns = [Narrative(narrative_id="__custom__", name="Custom", phases=[], raw={}, playbooks=[pb])]
    # matches above the threshold
    assert select_playbook(ns, phase="impact", confidence=0.9, mode="auto") is pb
    # gated below min_confidence on the auto path
    assert select_playbook(ns, phase="impact", confidence=0.1, mode="auto") is None
    # manual path is lenient
    assert select_playbook(ns, phase="impact", confidence=0.1, mode="manual") is pb
