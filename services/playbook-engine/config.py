"""Configuration for the playbook-engine service."""

from __future__ import annotations

from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict


class PlaybookEngineConfig(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", case_sensitive=False)

    database_url: str = "postgresql://vigil:changeme@localhost:5433/vigil"

    # Temporal.
    temporal_host: str = "localhost:7233"
    temporal_namespace: str = "vigil"
    temporal_task_queue: str = "vigil-playbooks"

    # Kafka.
    kafka_bootstrap_servers: str = "localhost:9092"
    kafka_topic_attacks_escalated: str = "vigil.attacks.escalated"
    kafka_topic_playbooks_paused: str = "vigil.playbooks.paused"
    kafka_consumer_group: str = "vigil-playbook-engine"

    # Outbound calls.
    attack_state_engine_url: str = "http://localhost:8002"
    internal_api_key: str = "dev-internal-key-change-me"

    # Narratives directory (response_playbooks live here).
    narratives_path: str = "attack-narratives"

    # API.
    port: int = 8007
    log_level: str = "INFO"
    cors_allow_origins: str = "http://localhost:5173,http://localhost:3000"

    # Auth — shared with services/api.
    auth_secret: str = "dev-only-secret-change-me"
    environment: str = "production"

    @property
    def cors_origins(self) -> list[str]:
        return [o.strip() for o in self.cors_allow_origins.split(",") if o.strip()]


_config: Optional[PlaybookEngineConfig] = None


def get_config() -> PlaybookEngineConfig:
    global _config
    if _config is None:
        _config = PlaybookEngineConfig()
    return _config
