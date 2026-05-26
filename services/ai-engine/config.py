"""Configuration for the AI engine."""

from __future__ import annotations

from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict


class AIEngineConfig(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", case_sensitive=False)

    port: int = 8006
    log_level: str = "INFO"

    anthropic_api_key: str = ""
    anthropic_model: str = "claude-sonnet-4-6"
    # Kill switch: when false, the narrator short-circuits to a stub instead of
    # calling Claude. Set ANTHROPIC_ENABLED=false in demo/Railway envs to cap spend.
    anthropic_enabled: bool = True

    attack_state_engine_url: str = "http://localhost:8002"
    internal_api_key: str = "dev-internal-key-change-me"

    redis_url: str = "redis://localhost:6380/1"
    narrative_cache_ttl_seconds: int = 600
    # Consumer skips a Claude call if a cached narrative exists within this
    # confidence delta. Raise to absorb noisier demo data.
    confidence_delta_skip: float = 0.15

    kafka_bootstrap_servers: str = "localhost:9092"
    kafka_topic_attacks_created: str = "vigil.attacks.created"
    kafka_topic_attacks_updated: str = "vigil.attacks.updated"
    kafka_consumer_group: str = "vigil-ai-engine"


_config: Optional[AIEngineConfig] = None


def get_config() -> AIEngineConfig:
    global _config
    if _config is None:
        _config = AIEngineConfig()
    return _config


def reset_config_for_tests() -> None:
    global _config
    _config = None
