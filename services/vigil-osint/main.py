"""vigil-osint — OSINT enrichment connector service.

Enriches IOCs (domain/ip/url/email/hash/keyword) surfaced by detections and
AttackState. Connector pattern: translate -> execute -> normalize -> Observation.
Stateless MVP: observations are returned in the response, not persisted.
"""

from __future__ import annotations

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import get_config
from .connectors.registry import registry
from .routers import enrich

logger = structlog.get_logger(__name__)


def create_app() -> FastAPI:
    cfg = get_config()
    app = FastAPI(
        title="vigil-osint",
        description="OSINT enrichment connector service for VIGIL",
        version="0.1.0",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=cfg.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(enrich.router)

    @app.on_event("startup")
    async def _startup() -> None:
        registry.discover()
        logger.info(
            "osint.startup",
            port=cfg.port,
            connectors=[c.name for c in registry.all()],
        )

    @app.get("/health")
    async def health() -> dict:
        return {
            "status": "ok",
            "service": "vigil-osint",
            "connectors": [c.name for c in registry.all()],
        }

    return app


app = create_app()
