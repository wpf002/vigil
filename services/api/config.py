"""Configuration for the VIGIL auth service."""

from __future__ import annotations
from typing import Optional
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class APIConfig(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", case_sensitive=False)

    environment: str = "development"
    port: int = 8000
    log_level: str = "INFO"

    database_url: str = "postgresql://vigil:changeme@localhost:5433/vigil"

    auth_secret: str = "dev-only-secret-change-me"
    access_token_ttl_minutes: int = 60
    refresh_token_ttl_days: int = 30

    cors_allow_origins: list[str] = ["http://localhost:5173", "http://localhost:3000"]

    @field_validator("cors_allow_origins", mode="before")
    @classmethod
    def split_origins(cls, v):
        if isinstance(v, str):
            return [o.strip() for o in v.split(",") if o.strip()]
        return v


_config: Optional[APIConfig] = None


def get_config() -> APIConfig:
    global _config
    if _config is None:
        _config = APIConfig()
    return _config


def reset_config_for_tests() -> None:
    """Test helper — forces re-read of env on next get_config()."""
    global _config
    _config = None
