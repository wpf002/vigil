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

    # Hard daily call budget — Redis-backed, atomic, auto-resets at UTC midnight.
    # This is the load-bearing defense; the kill switch above is a soft toggle
    # that can be defeated by an env-var slip or an out-of-date deploy.
    # 0 disables Claude entirely (every call falls back to stub).
    anthropic_daily_call_budget: int = 50

    # Per-process consecutive-error trip — if Claude errors this many times in
    # a row, this replica disables the narrator until restart. Stops the
    # 30-second-poll-forever loop the moment something goes structurally wrong
    # (auth, schema, quota).
    anthropic_consecutive_error_limit: int = 5

    attack_state_engine_url: str = "http://localhost:8002"
    internal_api_key: str = "dev-internal-key-change-me"

    redis_url: str = "redis://localhost:6380/1"
    narrative_cache_ttl_seconds: int = 600
    # Consumer skips a Claude call when a cached narrative for the same attack
    # exists within this confidence delta. 0.15 absorbs typical demo progressions.
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
