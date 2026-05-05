"""Configuration for the attack-state-engine service."""

from __future__ import annotations
from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class AttackStateConfig(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", case_sensitive=False)

    database_url: str = "postgresql://vigil:changeme@localhost:5432/vigil"
    redis_url: str = "redis://localhost:6379/0"

    kafka_bootstrap_servers: str = "localhost:9092"
    kafka_topic_signals: str = "vigil.signals.raw"
    kafka_topic_attacks_created: str = "vigil.attacks.created"
    kafka_topic_attacks_updated: str = "vigil.attacks.updated"
    kafka_topic_attacks_escalated: str = "vigil.attacks.escalated"

    escalation_confidence_threshold: float = 0.70
    momentum_increasing_window_minutes: int = 30
    momentum_decreasing_threshold_minutes: int = 120

    port: int = 8002
    log_level: str = "INFO"

    cors_allow_origins: list[str] = ["http://localhost:5173", "http://localhost:3000"]
    jwt_audience: Optional[str] = None
    jwt_issuer: Optional[str] = None


_config: Optional[AttackStateConfig] = None


def get_config() -> AttackStateConfig:
    global _config
    if _config is None:
        _config = AttackStateConfig()
    return _config
