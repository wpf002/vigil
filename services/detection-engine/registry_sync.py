"""Sync detections/compiled/manifest.json into detection_versions on startup.

The compiled manifest is the source of truth for what detections currently
exist on the platform. On startup we load each entry and ensure a baseline
'1.0.0' active row exists for the platform tenant. This makes the governance
layer self-bootstrapping — analysts don't need to manually deploy D1–D4.
"""

from __future__ import annotations
import json
from pathlib import Path
from typing import Any
from uuid import UUID

import structlog

from .store import DetectionStore

logger = structlog.get_logger(__name__)


def _read_text(path: Path) -> str:
    if not path.exists():
        return ""
    try:
        return path.read_text(encoding="utf-8")
    except OSError as e:
        logger.warning("registry_sync.read_failed", path=str(path), error=str(e))
        return ""


def _resolve(repo_root: Path, manifest_value: str | None) -> Path | None:
    if not manifest_value:
        return None
    return repo_root / manifest_value


async def sync_manifest_to_store(
    *,
    store: DetectionStore,
    compiled_path: Path,
    yaml_path: Path,
    tenant_id: UUID,
) -> int:
    """Reads manifest.json under compiled_path and ensures a baseline active
    version exists for each detection. Returns the number of versions written.

    Idempotent: only inserts when no active version exists for the detection.
    """
    manifest_file = compiled_path / "manifest.json"
    if not manifest_file.exists():
        logger.warning("registry_sync.manifest_missing", path=str(manifest_file))
        return 0

    try:
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        logger.error("registry_sync.parse_failed", error=str(e))
        return 0

    # Repo root: compiled_path is .../detections/compiled, yaml is .../detections/yaml.
    # Pull paths from manifest values, which are repo-rooted.
    repo_root = compiled_path.parent.parent

    written = 0
    for detection_id, entry in manifest.items():
        if not isinstance(entry, dict):
            continue

        existing = await store.get_active_version(detection_id, tenant_id)
        if existing is not None:
            continue

        attack: dict[str, Any] = entry.get("attack") or {}
        state_impact: dict[str, Any] = entry.get("state_impact") or {}

        yaml_content = _read_text(_resolve(repo_root, entry.get("yaml_path")) or Path())
        compiled_spl = _read_text(_resolve(repo_root, entry.get("splunk_path")) or Path())
        compiled_kql = _read_text(_resolve(repo_root, entry.get("sentinel_path")) or Path())
        compiled_eql = _read_text(_resolve(repo_root, entry.get("elastic_path")) or Path())

        await store.upsert_version(
            detection_id=detection_id,
            version="1.0.0",
            yaml_content=yaml_content,
            compiled_spl=compiled_spl or None,
            compiled_kql=compiled_kql or None,
            compiled_eql=compiled_eql or None,
            att_ck_tactic=str(attack.get("tactic") or "unknown"),
            att_ck_technique=str(attack.get("technique_id") or attack.get("technique") or "unknown"),
            state_impact=state_impact,
            tenant_id=tenant_id,
            notes="Seeded from detections/compiled/manifest.json on startup",
        )
        written += 1
        logger.info(
            "registry_sync.seeded",
            detection_id=detection_id,
            tactic=attack.get("tactic"),
            technique_id=attack.get("technique_id"),
        )
    if written:
        logger.info("registry_sync.complete", versions_written=written)
    return written
