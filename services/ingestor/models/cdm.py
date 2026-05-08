"""
VIGIL Common Data Model (CDM)

Normalized event schema that all SIEM connectors map to.
Ensures consistent structure regardless of source SIEM.
"""

from __future__ import annotations
from datetime import datetime
from enum import Enum
from typing import Any, Optional
from uuid import UUID, uuid4
from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


class AlertStatus(str, Enum):
    NEW = "new"
    IN_TRIAGE = "in_triage"
    INVESTIGATING = "investigating"
    ESCALATED = "escalated"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
    CLOSED = "closed"


class EventCategory(str, Enum):
    AUTHENTICATION = "authentication"
    NETWORK = "network"
    ENDPOINT = "endpoint"
    CLOUD = "cloud"
    EMAIL = "email"
    WEB = "web"
    DATABASE = "database"
    APPLICATION = "application"
    IDENTITY = "identity"
    UNKNOWN = "unknown"


class SplunkMode(str, Enum):
    ES = "es"
    CORE = "core"
    HEC = "hec"


class SIEMMode(str, Enum):
    """Top-level dispatcher for the ingestor. Splunk modes overlap
    with SplunkMode values so existing callers continue to work.

    DEMO synthesizes CDM events on a fixed schedule — no real SIEM
    connection needed. Used for local dev so the full ingest →
    correlation → attack-state pipeline runs end-to-end without
    customer telemetry.
    """
    ES = "es"
    CORE = "core"
    HEC = "hec"
    SENTINEL = "sentinel"
    ELASTIC = "elastic"
    DEMO = "demo"


class UserEntity(BaseModel):
    username: Optional[str] = None
    user_id: Optional[str] = None
    domain: Optional[str] = None
    email: Optional[str] = None
    is_privileged: Optional[bool] = None
    department: Optional[str] = None


class HostEntity(BaseModel):
    hostname: Optional[str] = None
    ip: Optional[str] = None
    mac: Optional[str] = None
    os: Optional[str] = None
    fqdn: Optional[str] = None
    is_domain_controller: Optional[bool] = None
    asset_criticality: Optional[str] = None


class NetworkEntity(BaseModel):
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    direction: Optional[str] = None
    bytes_in: Optional[int] = None
    bytes_out: Optional[int] = None


class ProcessEntity(BaseModel):
    process_name: Optional[str] = None
    process_id: Optional[int] = None
    parent_process_name: Optional[str] = None
    parent_process_id: Optional[int] = None
    command_line: Optional[str] = None
    hash_md5: Optional[str] = None
    hash_sha256: Optional[str] = None
    path: Optional[str] = None


class FileEntity(BaseModel):
    file_name: Optional[str] = None
    file_path: Optional[str] = None
    file_hash: Optional[str] = None
    file_size: Optional[int] = None
    action: Optional[str] = None


class MITREMapping(BaseModel):
    tactic: Optional[str] = None
    tactic_id: Optional[str] = None
    technique: Optional[str] = None
    technique_id: Optional[str] = None
    sub_technique_id: Optional[str] = None


class CDMEvent(BaseModel):
    """
    Normalized event. All SIEM connectors map to this structure.
    Includes detection_id and state_impact for attack-state correlation.
    """
    event_id: UUID = Field(default_factory=uuid4)
    tenant_id: str
    source_event_id: str
    source_siem: str = "splunk"
    timestamp: datetime
    ingested_at: datetime = Field(default_factory=datetime.utcnow)
    category: EventCategory = EventCategory.UNKNOWN
    severity: Severity = Severity.UNKNOWN
    status: AlertStatus = AlertStatus.NEW
    title: str
    description: Optional[str] = None
    rule_name: Optional[str] = None
    rule_id: Optional[str] = None
    detection_id: Optional[str] = None          # Links to YAML detection definition
    state_impact: Optional[dict[str, Any]] = None  # phase, status, confidence_contribution
    user: Optional[UserEntity] = None
    host: Optional[HostEntity] = None
    network: Optional[NetworkEntity] = None
    process: Optional[ProcessEntity] = None
    file: Optional[FileEntity] = None
    mitre: Optional[MITREMapping] = None
    threat_objects: list[dict[str, Any]] = Field(default_factory=list)
    risk_score: Optional[float] = None
    urgency: Optional[str] = None
    raw_event: dict[str, Any] = Field(default_factory=dict)
    enrichment: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat(),
            UUID: lambda v: str(v),
        }


class SplunkNotableEvent(BaseModel):
    event_id: str
    source: Optional[str] = None
    rule_name: Optional[str] = None
    rule_id: Optional[str] = None
    severity: Optional[str] = None
    urgency: Optional[str] = None
    status: Optional[str] = None
    owner: Optional[str] = None
    src: Optional[str] = None
    dest: Optional[str] = None
    user: Optional[str] = None
    risk_score: Optional[float] = None
    mitre_technique: Optional[str] = None
    _time: Optional[str] = None
    search_name: Optional[str] = None
    raw: dict[str, Any] = Field(default_factory=dict)


class SplunkCoreAlert(BaseModel):
    sid: str
    search_name: str
    results: list[dict[str, Any]] = Field(default_factory=list)
    triggered_at: Optional[str] = None
    severity: Optional[str] = None
