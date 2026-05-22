"""Configuration for signal-translation."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict

# Repo root: services/signal-translation/config.py → repo root is parents[2]
_REPO_ROOT = Path(__file__).resolve().parents[2]


class CompilerConfig(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", case_sensitive=False)

    port: int = 8004
    log_level: str = "INFO"

    # Resolved against the repo root if relative.
    detections_yaml_dir: str = "detections/yaml"
    detections_compiled_dir: str = "detections/compiled"

    @property
    def yaml_path(self) -> Path:
        p = Path(self.detections_yaml_dir)
        return p if p.is_absolute() else _REPO_ROOT / p

    @property
    def compiled_path(self) -> Path:
        p = Path(self.detections_compiled_dir)
        return p if p.is_absolute() else _REPO_ROOT / p


_config: Optional[CompilerConfig] = None


def get_config() -> CompilerConfig:
    global _config
    if _config is None:
        _config = CompilerConfig()
    return _config


def reset_config_for_tests() -> None:
    global _config
    _config = None
