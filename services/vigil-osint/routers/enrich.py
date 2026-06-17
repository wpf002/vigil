"""OSINT enrichment router.

POST /osint/enrich       — parse a query, fan out to capable connectors, return
                           canonical Observations (or deep_links when a
                           connector's policy forbids automation).
GET  /osint/entities/:value — Phase 2 persistence stub (no DB in MVP).
"""

from __future__ import annotations

import asyncio
from typing import Any, Optional

import structlog
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from ..connectors.registry import registry
from ..middleware.auth import TenantPrincipal, get_principal
from ..models.observation import Observation
from ..uql.parser import parse

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/osint", tags=["osint"])


class EnrichRequest(BaseModel):
    query: str
    connectors: list[str] = Field(default_factory=list)  # empty = all capable
    filters: dict[str, Any] = Field(default_factory=dict)


class ParsedQuery(BaseModel):
    type: str
    value: str


class DeepLink(BaseModel):
    connector: str
    url: str
    reason: str


class EnrichResponse(BaseModel):
    parsed: ParsedQuery
    observations: list[Observation]
    deep_links: list[DeepLink]
    errors: list[dict[str, str]] = Field(default_factory=list)


async def _run_connector(connector, uql) -> tuple[list[Observation], Optional[dict[str, str]]]:
    """Execute one connector off the event loop (httpx is sync)."""
    try:
        provider_query = connector.translate(uql)
        raw = await asyncio.to_thread(connector.execute, provider_query, {})
        return connector.normalize(raw), None
    except Exception as e:  # noqa: BLE001
        logger.warning("osint.connector.failed", connector=connector.name, error=str(e))
        return [], {"connector": connector.name, "error": str(e)}


@router.post("/enrich", response_model=EnrichResponse)
async def enrich(
    body: EnrichRequest,
    principal: TenantPrincipal = Depends(get_principal),
) -> EnrichResponse:
    uql = parse(body.query)
    requested = body.connectors or None
    candidates = registry.capable(uql.type, requested)

    logger.info(
        "osint.enrich",
        tenant_id=principal.tenant_id,
        entity_type=uql.type,
        entity_value=uql.value,
        connectors=[c.name for c in candidates],
    )

    observations: list[Observation] = []
    deep_links: list[DeepLink] = []
    errors: list[dict[str, str]] = []

    automatable = []
    for connector in candidates:
        if connector.policy.allow_automation:
            automatable.append(connector)
        else:
            # Policy forbids automated execution → hand back a link instead.
            deep_links.append(DeepLink(
                connector=connector.name,
                url=connector.deep_link_for(uql),
                reason="automation_disabled_by_policy",
            ))

    if automatable:
        results = await asyncio.gather(*(_run_connector(c, uql) for c in automatable))
        for obs, err in results:
            observations.extend(obs)
            if err:
                errors.append(err)

    return EnrichResponse(
        parsed=ParsedQuery(type=uql.type, value=uql.value),
        observations=observations,
        deep_links=deep_links,
        errors=errors,
    )


@router.get("/entities/{value}")
async def get_entity(
    value: str,
    principal: TenantPrincipal = Depends(get_principal),
) -> dict[str, Any]:
    """Phase 2 persistence stub. No observation store in the MVP — enrich is
    request/response only. This endpoint exists so the contract is stable for
    when the PostgreSQL entity store lands."""
    return {
        "value": value,
        "observations": [],
        "persisted": False,
        "note": "Entity persistence ships in Phase 2 (PostgreSQL). MVP is stateless.",
    }
