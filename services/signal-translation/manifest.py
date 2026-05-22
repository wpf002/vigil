"""Compiled-detection manifest.

manifest.json maps detection_id → { paths, ATT&CK metadata, state impact }
so consumers (correlation engine, control plane) don't need to re-parse YAML.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def write_manifest(manifest: dict[str, Any], compiled_dir: Path) -> Path:
    """Write manifest deterministically. Returns the manifest path."""
    compiled_dir.mkdir(parents=True, exist_ok=True)
    target = compiled_dir / "manifest.json"
    # sort_keys for determinism — same input must produce identical bytes.
    payload = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    target.write_text(payload, encoding="utf-8")
    return target


def read_manifest(compiled_dir: Path) -> dict[str, Any]:
    target = compiled_dir / "manifest.json"
    if not target.exists():
        return {}
    return json.loads(target.read_text(encoding="utf-8"))
