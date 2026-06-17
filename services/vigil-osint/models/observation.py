"""The canonical OSINT output. Every connector normalizes to an Observation."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class EntityType(str, Enum):
    DOMAIN = "domain"
    IP = "ip"
    URL = "url"
    EMAIL = "email"
    HASH = "hash"
    CERT = "cert"
    KEYWORD = "keyword"


class TLP(str, Enum):
    WHITE = "TLP:WHITE"
    GREEN = "TLP:GREEN"
    AMBER = "TLP:AMBER"
    RED = "TLP:RED"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class Observation(BaseModel):
    """Normalized OSINT finding. UI-safe `summary`, full `raw`, TLP + confidence
    on every record. `deep_link` is populated instead of data when a connector's
    policy forbids automated execution."""

    source: str
    entity_type: str
    entity_value: str
    observed_at: Optional[str] = None          # when the source observed this (ISO8601)
    retrieved_at: str = Field(default_factory=_now_iso)  # when VIGIL fetched it
    confidence_score: float = Field(default=0.5, ge=0.0, le=1.0)
    tlp: str = TLP.WHITE.value
    summary: dict[str, Any] = Field(default_factory=dict)
    raw: dict[str, Any] = Field(default_factory=dict)
    deep_link: Optional[str] = None
