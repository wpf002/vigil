"""Tests for the structured playbook trigger model (auto vs manual)."""

from __future__ import annotations

from playbook_engine.narrative_loader import (
    Narrative,
    Playbook,
    _parse_trigger,
    select_playbook,
)


def _pb(name, **t) -> Playbook:
    return Playbook(
        narrative_id="N", playbook_name=name, trigger=t.get("trigger", ""),
        trigger_mode=t.get("mode", "auto"),
        trigger_phase=t.get("phase"),
        trigger_status=t.get("status"),
        min_confidence=t.get("min_confidence", 0.0),
        trigger_detection_id=t.get("detection_id"),
    )


def _ns(*pbs) -> list[Narrative]:
    return [Narrative(narrative_id="N", name="N", phases=[], raw={}, playbooks=list(pbs))]


def test_parse_string_trigger():
    t = _parse_trigger("phase=credential-access AND status=Confirmed AND confidence>=0.65")
    assert t["phase"] == "credential-access"
    assert t["status"] == "Confirmed"
    assert t["min_confidence"] == 0.65
    assert t["mode"] == "auto"


def test_parse_dict_trigger():
    t = _parse_trigger({"mode": "manual", "phase": "impact", "min_confidence": 0.5})
    assert t["mode"] == "manual"
    assert t["phase"] == "impact"
    assert t["min_confidence"] == 0.5


def test_auto_enforces_min_confidence():
    pb = _pb("p", phase="credential-access", status="Confirmed", min_confidence=0.65)
    ns = _ns(pb)
    assert select_playbook(ns, phase="credential-access", status="Confirmed",
                           confidence=0.4, mode="auto") is None
    assert select_playbook(ns, phase="credential-access", status="Confirmed",
                           confidence=0.7, mode="auto") is pb


def test_auto_requires_status_match():
    pb = _pb("p", phase="credential-access", status="Confirmed", min_confidence=0.0)
    ns = _ns(pb)
    assert select_playbook(ns, phase="credential-access", status="Observed",
                           confidence=0.9, mode="auto") is None


def test_manual_is_lenient():
    pb = _pb("p", phase="credential-access", status="Confirmed", min_confidence=0.65)
    ns = _ns(pb)
    # wrong status + low confidence still runs on the manual path
    assert select_playbook(ns, phase="credential-access", status="Observed",
                           confidence=0.1, mode="manual") is pb


def test_manual_only_playbook_excluded_from_auto():
    pb = _pb("m", phase="exfiltration", mode="manual")
    ns = _ns(pb)
    assert select_playbook(ns, phase="exfiltration", confidence=0.9, mode="auto") is None
    assert select_playbook(ns, phase="exfiltration", confidence=0.0, mode="manual") is pb


def test_detection_id_constraint():
    pb = _pb("d", phase="execution", detection_id="D5-POWERSHELL-ENCODED-COMMAND")
    ns = _ns(pb)
    assert select_playbook(ns, phase="execution", confidence=0.9, mode="auto",
                           detection_ids=["D1-OTHER"]) is None
    assert select_playbook(ns, phase="execution", confidence=0.9, mode="auto",
                           detection_ids=["D5-POWERSHELL-ENCODED-COMMAND"]) is pb


def test_most_specific_wins():
    generic = _pb("generic", phase="credential-access", min_confidence=0.0)
    specific = _pb("specific", phase="credential-access", status="Confirmed", min_confidence=0.6)
    ns = _ns(generic, specific)
    chosen = select_playbook(ns, phase="credential-access", status="Confirmed",
                             confidence=0.8, mode="auto")
    assert chosen is specific
