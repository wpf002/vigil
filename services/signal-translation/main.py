"""VIGIL Signal Translation Service.

Wraps the detection compiler with a small REST API so the analyst portal
and control plane can query coverage and trigger recompiles.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import structlog
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .compiler import (
    BACKEND_LOGIC_KEY,
    compile_all,
    coverage_report,
    discover_yaml_files,
    load_yaml,
)
from .config import CompilerConfig, get_config
from .manifest import read_manifest
from .validator import ValidationError, validate

logger = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    cfg = get_config()
    app.state.config = cfg
    logger.info(
        "signal_translation.started",
        port=cfg.port,
        yaml_dir=str(cfg.yaml_path),
        compiled_dir=str(cfg.compiled_path),
    )
    yield


def create_app() -> FastAPI:
    app = FastAPI(title="VIGIL Signal Translation", version="0.1.0", lifespan=lifespan)

    cfg = get_config()
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/health")
    async def health():
        return {"status": "ok", "service": "signal-translation", "version": "0.1.0"}

    @app.get("/manifest")
    async def manifest():
        return read_manifest(cfg.compiled_path)

    @app.get("/detections")
    async def list_detections():
        m = read_manifest(cfg.compiled_path)
        # Sort by detection_id for deterministic ordering.
        return [
            {"detection_id": did, **entry}
            for did, entry in sorted(m.items())
        ]

    @app.get("/detections/{detection_id}")
    async def get_detection(detection_id: str):
        m = read_manifest(cfg.compiled_path)
        entry = m.get(detection_id) or m.get(detection_id.upper())
        if entry is None:
            raise HTTPException(status_code=404, detail="Detection not found")

        # Inline the compiled queries.
        def _read_if(key: str) -> str | None:
            rel = entry.get(key)
            if not rel:
                return None
            full = cfg.compiled_path.parent / rel
            return full.read_text(encoding="utf-8") if full.exists() else None

        return {
            "detection_id": detection_id,
            **entry,
            "compiled": {
                "splunk": _read_if("splunk_path"),
                "sentinel": _read_if("sentinel_path"),
                "elastic": _read_if("elastic_path"),
            },
        }

    @app.post("/compile")
    async def compile_endpoint():
        try:
            report = compile_all(cfg.yaml_path, cfg.compiled_path)
        except ValidationError as e:
            return JSONResponse(
                status_code=400,
                content={
                    "error": "Validation failed",
                    "results": [
                        {"detection_id": r.detection_id, "errors": r.errors}
                        for r in e.results
                    ],
                },
            )
        return {
            "compiled": [c.detection_id for c in report.compiled],
            "count": len(report.compiled),
        }

    @app.post("/compile/{detection_id}")
    async def compile_one(detection_id: str):
        # Find the matching YAML file, validate, then compile-all (so the
        # manifest stays consistent — single-detection writes would leave
        # the manifest out of sync with disk).
        files = discover_yaml_files(cfg.yaml_path)
        target_doc: dict[str, Any] | None = None
        for path in files:
            try:
                doc = load_yaml(path)
            except Exception:
                continue
            if isinstance(doc, dict) and str(doc.get("detection_id", "")).lower() == detection_id.lower():
                target_doc = doc
                break
        if target_doc is None:
            raise HTTPException(status_code=404, detail="Detection YAML not found")

        result = validate(target_doc)
        if not result.ok:
            return JSONResponse(
                status_code=400,
                content={"error": "Validation failed", "errors": result.errors},
            )

        report = compile_all(cfg.yaml_path, cfg.compiled_path)
        return {
            "compiled": detection_id,
            "total_compiled": len(report.compiled),
        }

    @app.get("/coverage")
    async def coverage():
        return coverage_report(cfg.yaml_path)

    return app


app = create_app()
