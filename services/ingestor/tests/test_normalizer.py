"""Normalizer unit tests — no live Splunk or Kafka required."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from ..models.cdm import AlertStatus, EventCategory, Severity, SplunkCoreAlert, SplunkNotableEvent
from ..normalizer.normalizer import EventNormalizer

TENANT_ID = "test-tenant"


@pytest.fixture
def normalizer():
    return EventNormalizer()


@pytest.fixture
def es_notable_critical():
    return SplunkNotableEvent(
        event_id="abc-123", source="WinEventLog:Security",
        rule_name="Brute Force - Multiple Failed Logins", rule_id="rule-001",
        severity="critical", urgency="critical", status="0",
        src="192.168.1.100", dest="10.0.0.50", user="CORP\\jsmith",
        risk_score=85.0, mitre_technique="Brute Force", _time="1720000000.0",
        raw={
            "event_id": "abc-123", "severity": "critical", "urgency": "critical",
            "status": "0", "src": "192.168.1.100", "dest": "10.0.0.50",
            "src_ip": "192.168.1.100", "dest_ip": "10.0.0.50",
            "user": "CORP\\jsmith", "risk_score": "85.0",
            "mitre_technique": "Brute Force", "mitre_technique_id": "T1110",
            "mitre_tactic": "Credential Access", "mitre_tactic_id": "TA0006",
            "_time": "1720000000.0",
        },
    )


@pytest.fixture
def es_notable_powershell():
    return SplunkNotableEvent(
        event_id="def-456", rule_name="Suspicious PowerShell Execution",
        severity="medium", status="1", dest="WORKSTATION01", user="jdoe",
        _time="1720001000.0",
        raw={
            "event_id": "def-456", "severity": "medium", "status": "1",
            "dest": "WORKSTATION01", "user": "jdoe",
            "process_name": "powershell.exe", "process_id": "4821",
            "CommandLine": "powershell.exe -EncodedCommand dABlAHMAdAA=",
            "ParentImage": "cmd.exe", "mitre_technique_id": "T1059.001",
            "mitre_tactic": "Execution", "_time": "1720001000.0",
        },
    )


@pytest.fixture
def core_alert():
    return SplunkCoreAlert(
        sid="scheduler__admin__RMD5f0123456",
        search_name="VIGIL - DNS Exfiltration Detection",
        triggered_at="1720002000.0", severity="high",
        results=[{
            "_time": "1720002000.0", "src_ip": "10.0.1.55",
            "dest_ip": "8.8.8.8", "dest_port": "53",
            "host": "SERVER01", "user": "svc_backup", "protocol": "udp",
        }],
    )


class TestNormalizerES:
    def test_basic_fields(self, normalizer, es_notable_critical):
        e = normalizer.normalize_notable_event(es_notable_critical, TENANT_ID)
        assert e.tenant_id == TENANT_ID
        assert e.source_event_id == "abc-123"
        assert e.source_siem == "splunk_es"
        assert e.severity == Severity.CRITICAL
        assert e.status == AlertStatus.NEW

    def test_user_domain_parsing(self, normalizer, es_notable_critical):
        e = normalizer.normalize_notable_event(es_notable_critical, TENANT_ID)
        assert e.user.username == "jsmith"
        assert e.user.domain == "CORP"

    def test_network_extraction(self, normalizer, es_notable_critical):
        e = normalizer.normalize_notable_event(es_notable_critical, TENANT_ID)
        assert e.network.src_ip == "192.168.1.100"
        assert e.network.dst_ip == "10.0.0.50"

    def test_mitre_extraction(self, normalizer, es_notable_critical):
        e = normalizer.normalize_notable_event(es_notable_critical, TENANT_ID)
        assert e.mitre.technique_id == "T1110"
        assert e.mitre.tactic == "Credential Access"

    def test_category_from_mitre_tactic(self, normalizer, es_notable_critical):
        e = normalizer.normalize_notable_event(es_notable_critical, TENANT_ID)
        assert e.category == EventCategory.IDENTITY

    def test_process_extraction(self, normalizer, es_notable_powershell):
        e = normalizer.normalize_notable_event(es_notable_powershell, TENANT_ID)
        assert e.process.process_name == "powershell.exe"
        assert e.process.process_id == 4821
        assert e.process.parent_process_name == "cmd.exe"

    def test_status_in_triage(self, normalizer, es_notable_powershell):
        e = normalizer.normalize_notable_event(es_notable_powershell, TENANT_ID)
        assert e.status == AlertStatus.IN_TRIAGE

    def test_risk_score(self, normalizer, es_notable_critical):
        e = normalizer.normalize_notable_event(es_notable_critical, TENANT_ID)
        assert e.risk_score == 85.0

    def test_raw_preserved(self, normalizer, es_notable_critical):
        e = normalizer.normalize_notable_event(es_notable_critical, TENANT_ID)
        assert e.raw_event.get("event_id") == "abc-123"

    def test_tags_built(self, normalizer, es_notable_critical):
        e = normalizer.normalize_notable_event(es_notable_critical, TENANT_ID)
        assert "mitre:T1110" in e.tags
        assert "severity:critical" in e.tags


class TestNormalizerCore:
    def test_produces_events(self, normalizer, core_alert):
        events = normalizer.normalize_core_alert(core_alert, TENANT_ID)
        assert len(events) == 1

    def test_source_siem(self, normalizer, core_alert):
        e = normalizer.normalize_core_alert(core_alert, TENANT_ID)[0]
        assert e.source_siem == "splunk_core"

    def test_severity(self, normalizer, core_alert):
        e = normalizer.normalize_core_alert(core_alert, TENANT_ID)[0]
        assert e.severity == Severity.HIGH

    def test_network_fields(self, normalizer, core_alert):
        e = normalizer.normalize_core_alert(core_alert, TENANT_ID)[0]
        assert e.network.src_ip == "10.0.1.55"
        assert e.network.dst_port == 53

    def test_privileged_user_detection(self, normalizer, core_alert):
        e = normalizer.normalize_core_alert(core_alert, TENANT_ID)[0]
        assert e.user.username == "svc_backup"
        assert e.user.is_privileged is True


class TestUtilities:
    def test_severity_unknown_on_none(self, normalizer):
        assert normalizer._map_severity(None) == Severity.UNKNOWN

    def test_severity_case_insensitive(self, normalizer):
        assert normalizer._map_severity("CRITICAL") == Severity.CRITICAL

    def test_severity_numeric(self, normalizer):
        assert normalizer._map_severity("5") == Severity.CRITICAL

    def test_ip_detection(self, normalizer):
        assert normalizer._is_ip("192.168.1.1") is True
        assert normalizer._is_ip("WORKSTATION01") is False

    def test_time_parsing_epoch(self, normalizer):
        dt = normalizer._parse_splunk_time("1720000000.0")
        assert isinstance(dt, datetime)
        assert dt.tzinfo is not None
