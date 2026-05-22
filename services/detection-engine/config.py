"""Configuration for the detection-engine service."""

from __future__ import annotations

from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict


class DetectionEngineConfig(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", case_sensitive=False)

    database_url: str = "postgresql://vigil:changeme@localhost:5433/vigil"

    port: int = 8005
    log_level: str = "INFO"
    cors_allow_origins: str = "http://localhost:5173,http://localhost:3000"

    # Shared with services/api so user JWTs validate here too.
    auth_secret: str = "dev-only-secret-change-me"
    environment: str = "production"

    # Internal service-to-service key (correlation-engine recording signal fires).
    internal_api_key: str = "dev-internal-key-change-me"

    # Path to the compiled detections directory (manifest.json + SIEM artifacts).
    # Resolved relative to repo root when running locally.
    detections_compiled_path: str = "detections/compiled"
    detections_yaml_path: str = "detections/yaml"

    # Default tenant_id used when seeding the platform's built-in detections
    # on startup. Tenant-scoped operations still gate on JWT.
    platform_tenant_id: str = "00000000-0000-0000-0000-000000000000"

    # Background performance aggregation interval.
    performance_interval_seconds: int = 3600

    # Signal-translation service used by rollback to recompile prior YAML.
    signal_translation_url: str = "http://localhost:8004"

    @property
    def cors_origins(self) -> list[str]:
        return [o.strip() for o in self.cors_allow_origins.split(",") if o.strip()]


_config: Optional[DetectionEngineConfig] = None


def get_config() -> DetectionEngineConfig:
    global _config
    if _config is None:
        _config = DetectionEngineConfig()
    return _config
