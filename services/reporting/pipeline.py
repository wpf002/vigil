"""Server-side health aggregator.

Browsers can't reach all VIGIL services directly because not every service
ships permissive CORS. We do the fan-out from the reporting service, which
is already CORS-enabled, and surface a single payload to the FE.
"""

from __future__ import annotations

import asyncio
from typing import Any, Optional

import httpx
import structlog

logger = structlog.get_logger(__name__)


# Each service declares its public port and the hostname the reporting
# container uses to reach it. Compose-internal services resolve via their
# service name on the docker network; host-run services (attack-state-engine
# and correlation-engine) come through host.docker.internal.
SERVICES = [
    {"name": "API",                 "port": 8000, "host": "api"},
    {"name": "Ingestor",            "port": 8001, "host": "ingestor"},
    {"name": "Attack-State Engine", "port": 8002, "host": "host.docker.internal"},
    {"name": "Correlation Engine",  "port": 8003, "host": "host.docker.internal"},
    {"name": "Signal Translation",  "port": 8004, "host": "signal-translation"},
    {"name": "Detection Engine",    "port": 8005, "host": "detection-engine"},
    {"name": "AI Engine",           "port": 8006, "host": "ai-engine"},
    {"name": "Playbook Engine",     "port": 8007, "host": "playbook-engine"},
    {"name": "Analyst Portal",      "port": 8008, "host": "analyst-portal"},
    {"name": "Reporting",           "port": 8009, "host": "reporting"},
]


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
    url = f"http://{svc['host']}:{svc['port']}/health"
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
