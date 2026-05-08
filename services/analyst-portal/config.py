"""Configuration for the analyst-portal service."""

from __future__ import annotations
from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class AnalystPortalConfig(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", case_sensitive=False)

    database_url: str = "postgresql://vigil:changeme@localhost:5433/vigil"

    # Kafka — consumes attack escalations and paused playbook notifications.
    kafka_bootstrap_servers: str = "localhost:9092"
    kafka_topic_attacks_escalated: str = "vigil.attacks.escalated"
    kafka_topic_playbooks_paused: str = "vigil.playbooks.paused"
    kafka_consumer_group: str = "vigil-analyst-portal"

    # Outbound — proxy reads to attack-state-engine.
    attack_state_engine_url: str = "http://localhost:8002"
    internal_api_key: str = "dev-internal-key-change-me"

    # Default SLA tiers (minutes). Used to seed sla_configs for new tenants.
    sla_critical_minutes: int = 15
    sla_high_minutes: int = 30
    sla_medium_minutes: int = 60
    sla_low_minutes: int = 240

    # Background SLA monitor cadence.
    sla_monitor_interval_seconds: int = 60

    # API.
    port: int = 8008
    log_level: str = "INFO"
    cors_allow_origins: str = "http://localhost:5173,http://localhost:3000"

    # Auth.
    auth_secret: str = "dev-only-secret-change-me"
    environment: str = "production"

    @property
    def cors_origins(self) -> list[str]:
        return [o.strip() for o in self.cors_allow_origins.split(",") if o.strip()]


_config: Optional[AnalystPortalConfig] = None


def get_config() -> AnalystPortalConfig:
    global _config
    if _config is None:
        _config = AnalystPortalConfig()
    return _config
