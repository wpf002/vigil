"""Correlation engine configuration."""

from __future__ import annotations

from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict


class CorrelationConfig(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", case_sensitive=False)

    database_url: str = "postgresql://vigil:changeme@localhost:5432/vigil"
    redis_url: str = "redis://localhost:6379/0"

    kafka_bootstrap_servers: str = "localhost:9092"
    kafka_topic_signals: str = "vigil.signals.raw"
    kafka_topic_attacks_created: str = "vigil.attacks.created"
    kafka_topic_attacks_updated: str = "vigil.attacks.updated"
    kafka_topic_attacks_escalated: str = "vigil.attacks.escalated"
    kafka_consumer_group: str = "vigil-correlation-engine"

    # Idempotency: signal IDs we have already processed
    idempotency_ttl_seconds: int = 60 * 60 * 24  # 24 hours

    # Entity → attack_id cache TTL
    entity_index_ttl_seconds: int = 60 * 60 * 2  # 2 hours

    # Distributed lock for entity-keyed attack lookup/create critical section
    lock_ttl_seconds: int = 10

    # Detections registry — would normally be loaded from YAML or a service.
    # For Phase 1 this is a minimal in-process map until detections compile to JSON.
    detections_registry_path: Optional[str] = None

    port: int = 8003
    log_level: str = "INFO"

    # detection-engine endpoint for fire-and-forget signal recording.
    # Empty string disables the call entirely.
    detection_engine_url: str = "http://localhost:8005"
    internal_api_key: str = "dev-internal-key-change-me"


_config: Optional[CorrelationConfig] = None


def get_config() -> CorrelationConfig:
    global _config
    if _config is None:
        _config = CorrelationConfig()
    return _config
