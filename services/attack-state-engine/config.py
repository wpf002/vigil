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

    cors_allow_origins: str = "http://localhost:5173,http://localhost:3000"
    jwt_audience: Optional[str] = None
    jwt_issuer: Optional[str] = None

    @property
    def cors_origins(self) -> list[str]:
        return [o.strip() for o in self.cors_allow_origins.split(",") if o.strip()]

    # Shared with services/api. MUST be the same value across both services.
    auth_secret: str = "dev-only-secret-change-me"
    environment: str = "production"

    # Internal service-to-service key (e.g. ai-engine PATCHing narratives).
    internal_api_key: str = "dev-internal-key-change-me"

    # Demo auto-resolver: periodically resolves a fraction of aged attacks so
    # MTTR/SLA metrics populate without requiring a real analyst. Off by default.
    auto_resolve_enabled: bool = False
    auto_resolve_interval_seconds: int = 90
    auto_resolve_min_age_minutes: int = 8
    auto_resolve_fraction: float = 0.4


_config: Optional[AttackStateConfig] = None


def get_config() -> AttackStateConfig:
    global _config
    if _config is None:
        _config = AttackStateConfig()
    return _config
