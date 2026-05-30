"""Tests for the enrichment vs response action split."""

from __future__ import annotations

from playbook_engine.narrative_loader import (
    ENRICHMENT_ACTION_TYPES,
    Playbook,
    PlaybookAction,
    _load_action,
    classify_kind,
    render_actions_for,
)


def test_classify_kind():
    assert classify_kind("ioc_lookup") == "enrichment"
    assert classify_kind("user_context") == "enrichment"
    assert classify_kind("isolate_host") == "response"
    assert classify_kind("totally_unknown") == "response"


def test_load_action_infers_kind():
    assert _load_action({"action": "ioc_lookup", "target": "1.2.3.4"}).kind == "enrichment"
    assert _load_action({"action": "isolate_host", "target": "host"}).kind == "response"


def test_load_action_explicit_kind_wins():
    # an operator can force a normally-response action to be enrichment-only
    a = _load_action({"action": "review_auth_logs", "target": "h", "kind": "enrichment"})
    assert a.kind == "enrichment"


def test_to_response_action_includes_kind():
    a = PlaybookAction(action_type="ioc_lookup", target="ioc", kind="enrichment")
    out = a.to_response_action(priority="immediate", target_entity="1.2.3.4")
    assert out["kind"] == "enrichment"
    assert out["action_type"] == "ioc_lookup"


def test_render_carries_kind():
    pb = Playbook(
        narrative_id="AN-01", playbook_name="p", trigger="t",
        immediate=[
            PlaybookAction(action_type="ioc_lookup", target="affected_host", kind="enrichment"),
            PlaybookAction(action_type="isolate_host", target="affected_host", kind="response"),
        ],
    )
    rendered = render_actions_for(pb, primary_host="HOST-1", primary_user=None)
    kinds = {r["action_type"]: r["kind"] for r in rendered}
    assert kinds["ioc_lookup"] == "enrichment"
    assert kinds["isolate_host"] == "response"


def test_enrichment_set_is_read_only_actions():
    # sanity: the canonical enrichment set never contains a state-changing verb
    for verb in ("isolate", "kill", "reset", "block", "disable"):
        assert not any(verb in a for a in ENRICHMENT_ACTION_TYPES)
