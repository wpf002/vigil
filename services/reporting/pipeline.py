"""Server-side health aggregator.

Browsers can't reach all VIGIL services directly because not every service
ships permissive CORS. We do the fan-out from the reporting service, which
is already CORS-enabled, and surface a single payload to the FE.
"""

from __future__ import annotations

import asyncio
import os
from typing import Any, Optional

import httpx
import structlog

logger = structlog.get_logger(__name__)


# Each service declares its public port and the hostname the reporting
# container uses to reach it. Compose-internal services resolve via their
# service name on the docker network; host-run services (attack-state-engine
# and correlation-engine) come through host.docker.internal.
#
# `env` names an environment variable holding the service's full base URL.
# When set (Railway injects `*.railway.internal` URLs there) it overrides the
# compose host:port, so the same probe works on both Docker compose and
# Railway's private network without code changes.
SERVICES = [
    {"name": "API",                 "port": 8000, "host": "api",                 "env": "API_URL"},
    {"name": "Ingestor",            "port": 8001, "host": "ingestor",            "env": "INGESTOR_URL"},
    {"name": "Attack-State Engine", "port": 8002, "host": "host.docker.internal", "env": "ATTACK_STATE_ENGINE_URL"},
    {"name": "Correlation Engine",  "port": 8003, "host": "host.docker.internal", "env": "CORRELATION_ENGINE_URL"},
    {"name": "Signal Translation",  "port": 8004, "host": "signal-translation",  "env": "SIGNAL_TRANSLATION_URL"},
    {"name": "Detection Engine",    "port": 8005, "host": "detection-engine",    "env": "DETECTION_ENGINE_URL"},
    {"name": "AI Engine",           "port": 8006, "host": "ai-engine",           "env": "AI_ENGINE_URL"},
    {"name": "Playbook Engine",     "port": 8007, "host": "playbook-engine",     "env": "PLAYBOOK_ENGINE_URL"},
    {"name": "Analyst Portal",      "port": 8008, "host": "analyst-portal",      "env": "ANALYST_PORTAL_URL"},
    {"name": "Reporting",           "port": 8009, "host": "reporting",           "env": "REPORTING_URL"},
]


def _health_url(svc: dict[str, Any]) -> str:
    """Resolve a service's /health URL, preferring its env-provided base URL."""
    base = os.environ.get(svc.get("env", "")) if svc.get("env") else None
    if base:
        return f"{base.rstrip('/')}/health"
    return f"http://{svc['host']}:{svc['port']}/health"


async def collect_pipeline_status(timeout: float = 3.0) -> dict[str, Any]:
    """Fan out parallel /health checks to every known VIGIL service."""
    async with httpx.AsyncClient(timeout=timeout) as client:
        results = await asyncio.gather(
            *[_probe(client, s) for s in SERVICES],
            return_exceptions=False,
        )
    healthy = sum(1 for r in results if r["ok"])
    return {
        "services": results,
        "summary": {
            "total": len(results),
            "healthy": healthy,
            "unreachable": len(results) - healthy,
        },
    }


async def _probe(client: httpx.AsyncClient, svc: dict[str, Any]) -> dict[str, Any]:
    """Three-state probe: ok | degraded | unreachable.

    A 503 with a JSON body is degraded — the service is up but reports
    itself unhealthy (e.g. ingestor with no SIEM configured). A connection
    error is unreachable.
    """
    url = _health_url(svc)
    try:
        resp = await client.get(url)
    except Exception as e:
        logger.debug("pipeline.probe.unreachable", port=svc["port"], error=str(e))
        return {
            "name": svc["name"],
            "port": svc["port"],
            "ok": False,
            "status": "unreachable",
            "version": None,
        }

    body: Any = None
    try:
        body = resp.json()
    except Exception:
        body = None

    reported = (body.get("status") if isinstance(body, dict) else None) or (
        "ok" if resp.status_code < 400 else "degraded"
    )
    ok = resp.status_code < 400 and reported == "ok"
    version = body.get("version") if isinstance(body, dict) else None

    return {
        "name": svc["name"],
        "port": svc["port"],
        "ok": bool(ok),
        "status": reported,
        "version": version,
    }
