from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict
from .models.cdm import SplunkMode


class IngestorConfig(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", case_sensitive=False)

    splunk_host: str
    splunk_username: Optional[str] = None
    splunk_password: Optional[str] = None
    splunk_token: Optional[str] = None
    splunk_mode: SplunkMode = SplunkMode.ES
    splunk_verify_ssl: bool = False
    splunk_poll_interval_seconds: int = 30
    splunk_max_events_per_poll: int = 500
    splunk_es_status_filter: list[str] = ["new"]
    splunk_es_severity_filter: list[str] = ["critical", "high", "medium"]

    kafka_bootstrap_servers: str = "localhost:9092"
    kafka_topic_signals: str = "vigil.signals.raw"

    redis_url: str = "redis://localhost:6379/0"
    elasticsearch_url: str = "http://localhost:9200"

    port: int = 8001
    log_level: str = "INFO"
    tenant_id: str = "default"


_config: Optional[IngestorConfig] = None


def get_config() -> IngestorConfig:
    global _config
    if _config is None:
        _config = IngestorConfig()
    return _config
