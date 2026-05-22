"""Tests for the YAML detection compiler.

Covers:
- valid YAML compiles correctly
- missing required field fails
- invalid confidence_contribution fails
- field normalization applied (canonical → backend names)
- manifest written with correct structure
- coverage report accurate
- compiler is idempotent (running twice produces identical output)
"""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest
import yaml

from signal_translation import normalizer
from signal_translation.compiler import (
    compile_all,
    coverage_report,
    discover_yaml_files,
)
from signal_translation.validator import (
    ValidationError,
    validate,
)

# ── helpers ─────────────────────────────────────────────────────────────────

def _good_detection(detection_id: str = "TEST-001", tactic: str = "credential-access") -> dict:
    return {
        "detection_id": detection_id,
        "name": "Test Detection",
        "att&ck": {
            "tactic": tactic,
            "tactic_id": "TA0006",
            "technique_id": "T1003",
            "technique": "OS Credential Dumping",
        },
        "state_impact": {
            "transitions_to": tactic,
            "status": "Observed",
            "confidence_contribution": 0.25,
            "progression": False,
        },
        "logic": {
            "splunk_spl": "search src_ip=10.0.0.1 hostname=DC-01 username=admin",
            "sentinel_kql": "Logs | where src_ip == '10.0.0.1' and hostname == 'DC-01'",
            "elastic_eql": "process where src_ip == '10.0.0.1' and hostname == 'DC-01'",
        },
    }


def _write_yaml(dirpath: Path, name: str, doc: dict) -> Path:
    path = dirpath / f"{name}.yaml"
    path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
    return path


# ── tests ───────────────────────────────────────────────────────────────────

def test_valid_yaml_compiles(tmp_path: Path):
    yaml_dir = tmp_path / "yaml"
    yaml_dir.mkdir()
    out_dir = tmp_path / "compiled"

    _write_yaml(yaml_dir, "ok", _good_detection())

    report = compile_all(yaml_dir, out_dir)
    assert len(report.compiled) == 1
    c = report.compiled[0]
    assert c.detection_id == "TEST-001"
    assert c.splunk_path.exists()
    assert c.sentinel_path.exists()
    assert c.elastic_path.exists()


def test_missing_required_field_fails(tmp_path: Path):
    bad = _good_detection()
    del bad["att&ck"]["technique_id"]

    yaml_dir = tmp_path / "yaml"
    yaml_dir.mkdir()
    out_dir = tmp_path / "compiled"
    _write_yaml(yaml_dir, "bad", bad)

    with pytest.raises(ValidationError):
        compile_all(yaml_dir, out_dir)


def test_invalid_confidence_contribution_fails(tmp_path: Path):
    bad = _good_detection()
    bad["state_impact"]["confidence_contribution"] = 1.5

    yaml_dir = tmp_path / "yaml"
    yaml_dir.mkdir()
    out_dir = tmp_path / "compiled"
    _write_yaml(yaml_dir, "bad", bad)

    with pytest.raises(ValidationError):
        compile_all(yaml_dir, out_dir)


def test_invalid_status_fails(tmp_path: Path):
    bad = _good_detection()
    bad["state_impact"]["status"] = "MaybeBad"

    yaml_dir = tmp_path / "yaml"
    yaml_dir.mkdir()
    out_dir = tmp_path / "compiled"
    _write_yaml(yaml_dir, "bad", bad)

    with pytest.raises(ValidationError):
        compile_all(yaml_dir, out_dir)


def test_invalid_tactic_fails(tmp_path: Path):
    bad = _good_detection()
    bad["state_impact"]["transitions_to"] = "not-a-real-tactic"

    yaml_dir = tmp_path / "yaml"
    yaml_dir.mkdir()
    out_dir = tmp_path / "compiled"
    _write_yaml(yaml_dir, "bad", bad)

    with pytest.raises(ValidationError):
        compile_all(yaml_dir, out_dir)


def test_field_normalization_applied(tmp_path: Path):
    yaml_dir = tmp_path / "yaml"
    yaml_dir.mkdir()
    out_dir = tmp_path / "compiled"
    _write_yaml(yaml_dir, "ok", _good_detection())

    report = compile_all(yaml_dir, out_dir)
    c = report.compiled[0]

    splunk_text = c.splunk_path.read_text(encoding="utf-8")
    sentinel_text = c.sentinel_path.read_text(encoding="utf-8")
    elastic_text = c.elastic_path.read_text(encoding="utf-8")

    # Splunk: src_ip → src, hostname → host, username → user.
    assert "src=10.0.0.1" in splunk_text
    assert "host=DC-01" in splunk_text
    assert "user=admin" in splunk_text
    # Original canonical names should not survive in the query (they may
    # appear in the comment header — strip the header before checking).
    body = splunk_text.split("\n\n", 1)[-1]
    assert "src_ip" not in body
    assert "hostname" not in body
    assert "username" not in body

    # Sentinel: src_ip → SourceIP, hostname → DeviceName.
    assert "SourceIP" in sentinel_text
    assert "DeviceName" in sentinel_text

    # Elastic: src_ip → source.ip, hostname → host.hostname.
    assert "source.ip" in elastic_text
    assert "host.hostname" in elastic_text


def test_manifest_structure(tmp_path: Path):
    yaml_dir = tmp_path / "yaml"
    yaml_dir.mkdir()
    out_dir = tmp_path / "compiled"
    _write_yaml(yaml_dir, "ok", _good_detection("D-A"))
    _write_yaml(yaml_dir, "second", _good_detection("D-B"))

    compile_all(yaml_dir, out_dir)
    manifest = json.loads((out_dir / "manifest.json").read_text())

    assert set(manifest.keys()) == {"D-A", "D-B"}
    entry = manifest["D-A"]
    assert entry["splunk_path"]
    assert entry["sentinel_path"]
    assert entry["elastic_path"]
    assert entry["attack"]["tactic"] == "credential-access"
    assert entry["state_impact"]["transitions_to"] == "credential-access"
    assert entry["state_impact"]["status"] == "Observed"
    assert entry["state_impact"]["confidence_contribution"] == 0.25


def test_compiler_is_idempotent(tmp_path: Path):
    yaml_dir = tmp_path / "yaml"
    yaml_dir.mkdir()
    out_dir = tmp_path / "compiled"
    _write_yaml(yaml_dir, "a", _good_detection("D-A"))
    _write_yaml(yaml_dir, "b", _good_detection("D-B", tactic="lateral-movement"))

    compile_all(yaml_dir, out_dir)
    first = _snapshot(out_dir)

    compile_all(yaml_dir, out_dir)
    second = _snapshot(out_dir)

    assert first == second, "Compiler output is not idempotent"


def _snapshot(root: Path) -> dict[str, str]:
    """Return file path → content map for byte-identical comparison."""
    return {
        str(p.relative_to(root)): p.read_text(encoding="utf-8")
        for p in sorted(root.rglob("*"))
        if p.is_file()
    }


def test_coverage_report_accurate(tmp_path: Path):
    yaml_dir = tmp_path / "yaml"
    yaml_dir.mkdir()
    _write_yaml(yaml_dir, "a", _good_detection("D-A", tactic="credential-access"))
    _write_yaml(yaml_dir, "b", _good_detection("D-B", tactic="lateral-movement"))
    _write_yaml(yaml_dir, "c", _good_detection("D-C", tactic="credential-access"))

    report = coverage_report(yaml_dir)
    assert report["detection_count"] == 3
    assert report["tactics_covered"]["credential-access"] == 2
    assert report["tactics_covered"]["lateral-movement"] == 1
    assert "exfiltration" in report["tactic_gaps"]


def test_normalizer_does_not_corrupt_subwords():
    # `username` should be replaced; `usernamespace` (a pretend identifier
    # containing the substring) must survive.
    spl = normalizer.for_splunk("username=alice usernamespace=foo")
    assert "user=alice" in spl
    assert "usernamespace=foo" in spl


def test_validator_collects_multiple_errors():
    bad = _good_detection()
    del bad["att&ck"]["technique_id"]
    bad["state_impact"]["confidence_contribution"] = -0.5
    result = validate(bad)
    assert not result.ok
    assert len(result.errors) >= 2


def test_compile_writes_header_to_artifacts(tmp_path: Path):
    yaml_dir = tmp_path / "yaml"
    yaml_dir.mkdir()
    out_dir = tmp_path / "compiled"
    _write_yaml(yaml_dir, "ok", _good_detection("D-HDR"))

    report = compile_all(yaml_dir, out_dir)
    spl_text = report.compiled[0].splunk_path.read_text(encoding="utf-8")
    assert "VIGIL compiled detection" in spl_text
    assert "detection_id: D-HDR" in spl_text
