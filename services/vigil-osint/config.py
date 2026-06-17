"""Configuration for vigil-osint.

JWT auth reuses VIGIL's shared HS256 secret (AUTH_SECRET) so a single user
token is valid across services — we never reimplement auth here.
"""

from __future__ import annotations

from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict


class OsintConfig(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", case_sensitive=False, extra="ignore")

    port: int = 8012
    log_level: str = "INFO"
    environment: str = "production"

    # Shared VIGIL JWT secret — same value as services/api so tokens are portable.
    auth_secret: str = "dev-only-secret-change-me"

    cors_origins: list[str] = ["*"]

    # urlscan.io passive search (no auth required on the free public endpoint).
    urlscan_base_url: str = "https://urlscan.io"
    http_timeout_seconds: float = 20.0
    max_observations_per_connector: int = 10


_config: Optional[OsintConfig] = None


def get_config() -> OsintConfig:
    global _config
    if _config is None:
        _config = OsintConfig()
    return _config
