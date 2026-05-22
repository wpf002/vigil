from __future__ import annotations

from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict


class ReportingConfig(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", case_sensitive=False)

    environment: str = "development"
    port: int = 8009
    log_level: str = "INFO"
    cors_allow_origins: str = "http://localhost:5173,http://localhost:3000"

    database_url: str = "postgresql://vigil:changeme@localhost:5433/vigil"
    redis_url: str = "redis://localhost:6379/2"

    auth_secret: str = "dev-only-secret-change-me"

    # Upstream service URLs.
    api_url: str = "http://localhost:8000"
    attack_state_engine_url: str = "http://localhost:8002"
    detection_engine_url: str = "http://localhost:8005"
    analyst_portal_url: str = "http://localhost:8008"

    internal_api_key: str = "dev-internal-key-change-me"

    # Cache TTL for executive summary / trend in seconds.
    cache_ttl_seconds: int = 300

    # Daily snapshot schedule (UTC). Hour=0, minute=5 means 00:05 UTC.
    snapshot_hour_utc: int = 0
    snapshot_minute_utc: int = 5

    @property
    def cors_origins(self) -> list[str]:
        return [o.strip() for o in self.cors_allow_origins.split(",") if o.strip()]


_config: Optional[ReportingConfig] = None


def get_config() -> ReportingConfig:
    global _config
    if _config is None:
        _config = ReportingConfig()
    return _config


def reset_config_for_tests() -> None:
    global _config
    _config = None
