"""YAML detection compiler.

Reads YAML detection files, validates, applies field normalization,
and emits backend-specific artifacts to detections/compiled/{splunk,sentinel,elastic}/.
A manifest.json maps detection_id → compiled paths and metadata.

The compiler is idempotent: running twice produces byte-identical output
for the same input.
"""

from __future__ import annotations
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import structlog
import yaml

from . import normalizer
from .manifest import write_manifest
from .validator import (
    ValidationError,
    ValidationResult,
    validate,
)

logger = structlog.get_logger(__name__)

BACKENDS = ("splunk", "sentinel", "elastic")
BACKEND_EXT = {"splunk": "spl", "sentinel": "kql", "elastic": "eql"}
BACKEND_LOGIC_KEY = {
    "splunk": "splunk_spl",
    "sentinel": "sentinel_kql",
    "elastic": "elastic_eql",
}
BACKEND_NORMALIZER = {
    "splunk": normalizer.for_splunk,
    "sentinel": normalizer.for_sentinel,
    "elastic": normalizer.for_elastic,
}
BACKEND_COMMENT = {"splunk": "#", "sentinel": "//", "elastic": "//"}


@dataclass
class CompiledDetection:
    detection_id: str
    name: str
    yaml_path: Path
    splunk_path: Optional[Path] = None
    sentinel_path: Optional[Path] = None
    elastic_path: Optional[Path] = None
    attack: dict[str, Any] = field(default_factory=dict)
    state_impact: dict[str, Any] = field(default_factory=dict)


# ── YAML loading ────────────────────────────────────────────────────────────

def discover_yaml_files(yaml_dir: Path) -> list[Path]:
    if not yaml_dir.exists():
        return []
    files = sorted(yaml_dir.rglob("*.yaml")) + sorted(yaml_dir.rglob("*.yml"))
    # Sort for determinism — rglob's order is filesystem-dependent.
    return sorted(set(files))


def load_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)


# ── Header injection ────────────────────────────────────────────────────────

def _build_header(detection: dict[str, Any], backend: str) -> str:
    """Comment header injected at the top of every compiled artifact.

    Authors should NEVER hand-edit compiled files; the header makes that
    intent explicit and pins which YAML the artifact came from.
    """
    comment = BACKEND_COMMENT[backend]
    attack = detection.get("att&ck") or detection.get("attack") or {}
    state_impact = detection.get("state_impact") or {}
    lines = [
        f"{comment} VIGIL compiled detection — DO NOT EDIT.",
        f"{comment} detection_id: {detection.get('detection_id')}",
        f"{comment} name: {detection.get('name')}",
        f"{comment} att&ck: {attack.get('tactic')} / {attack.get('technique_id')}",
        f"{comment} state_impact.transitions_to: {state_impact.get('transitions_to')}",
        f"{comment} state_impact.status: {state_impact.get('status')}",
        f"{comment} state_impact.confidence_contribution: {state_impact.get('confidence_contribution')}",
        f"{comment} source: managed by services/signal-translation",
        "",
    ]
    return "\n".join(lines)


# ── Compilation ─────────────────────────────────────────────────────────────

@dataclass
class CompileReport:
    compiled: list[CompiledDetection] = field(default_factory=list)
    validation_errors: list[ValidationResult] = field(default_factory=list)


def compile_detection(
    detection: dict[str, Any], compiled_dir: Path
) -> CompiledDetection:
    """Compile one detection. Caller is responsible for validation up front."""
    detection_id = str(detection["detection_id"])
    name = str(detection.get("name") or detection_id)
    logic = detection["logic"]

    record = CompiledDetection(
        detection_id=detection_id,
        name=name,
        yaml_path=Path(),  # filled in by compile_all
        attack=detection.get("att&ck") or detection.get("attack") or {},
        state_impact=detection.get("state_impact") or {},
    )

    for backend in BACKENDS:
        raw_query = str(logic[BACKEND_LOGIC_KEY[backend]]).strip("\n")
        normalized = BACKEND_NORMALIZER[backend](raw_query).strip("\n")
        header = _build_header(detection, backend)
        artifact = header + normalized + "\n"

        backend_dir = compiled_dir / backend
        backend_dir.mkdir(parents=True, exist_ok=True)
        out_path = backend_dir / f"{_slug(detection_id)}.{BACKEND_EXT[backend]}"
        out_path.write_text(artifact, encoding="utf-8")

        setattr(record, f"{backend}_path", out_path)

    return record


def _slug(detection_id: str) -> str:
    """Filesystem-safe slug. detection_id is already reasonably tame; we
    just lower-case and replace anything outside [A-Za-z0-9._-] with '-'.
    """
    return re.sub(r"[^A-Za-z0-9._-]+", "-", detection_id).strip("-").lower()


def compile_all(yaml_dir: Path, compiled_dir: Path) -> CompileReport:
    """Compile every YAML under ``yaml_dir`` into ``compiled_dir``.

    Raises ValidationError if any detection fails validation — partial
    output is still written for the ones that passed.
    """
    files = discover_yaml_files(yaml_dir)
    report = CompileReport()
    manifest: dict[str, Any] = {}

    rel_compiled_root = compiled_dir

    for path in files:
        try:
            doc = load_yaml(path)
        except yaml.YAMLError as e:
            report.validation_errors.append(
                ValidationResult(
                    detection_id=path.name,
                    errors=[f"YAML parse error: {e}"],
                )
            )
            continue

        if not isinstance(doc, dict):
            report.validation_errors.append(
                ValidationResult(
                    detection_id=path.name,
                    errors=["Top-level YAML must be a mapping"],
                )
            )
            continue

        result = validate(doc)
        if not result.ok:
            report.validation_errors.append(result)
            continue

        compiled = compile_detection(doc, compiled_dir)
        compiled.yaml_path = path
        report.compiled.append(compiled)

        manifest[compiled.detection_id] = {
            "name": compiled.name,
            "yaml_path": _rel(path, rel_compiled_root.parent),
            "splunk_path": _rel(compiled.splunk_path, rel_compiled_root.parent),
            "sentinel_path": _rel(compiled.sentinel_path, rel_compiled_root.parent),
            "elastic_path": _rel(compiled.elastic_path, rel_compiled_root.parent),
            "attack": {
                "tactic": compiled.attack.get("tactic"),
                "tactic_id": compiled.attack.get("tactic_id"),
                "technique": compiled.attack.get("technique"),
                "technique_id": compiled.attack.get("technique_id"),
            },
            "state_impact": {
                "transitions_to": compiled.state_impact.get("transitions_to"),
                "status": compiled.state_impact.get("status"),
                "confidence_contribution": compiled.state_impact.get(
                    "confidence_contribution"
                ),
                "progression": bool(compiled.state_impact.get("progression", False)),
            },
        }

    write_manifest(manifest, compiled_dir)

    if report.validation_errors:
        raise ValidationError(report.validation_errors)

    return report


def _rel(path: Optional[Path], root: Path) -> Optional[str]:
    if path is None:
        return None
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


# ── Coverage ────────────────────────────────────────────────────────────────

def coverage_report(yaml_dir: Path) -> dict[str, Any]:
    """Summarise ATT&CK coverage from raw YAML (no compile required)."""
    files = discover_yaml_files(yaml_dir)
    tactics: dict[str, int] = {}
    techniques: dict[str, int] = {}
    detections = 0

    for path in files:
        try:
            doc = load_yaml(path)
        except yaml.YAMLError:
            continue
        if not isinstance(doc, dict):
            continue
        attack = doc.get("att&ck") or doc.get("attack") or {}
        tactic = attack.get("tactic")
        technique = attack.get("technique_id")
        if tactic:
            tactics[tactic] = tactics.get(tactic, 0) + 1
        if technique:
            techniques[technique] = techniques.get(technique, 0) + 1
        detections += 1

    from .validator import VALID_TACTICS

    gaps = sorted(VALID_TACTICS - set(tactics.keys()))

    return {
        "detection_count": detections,
        "tactics_covered": dict(sorted(tactics.items())),
        "techniques_covered": dict(sorted(techniques.items())),
        "tactic_gaps": gaps,
    }
