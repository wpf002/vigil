from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict

from .models.cdm import SIEMMode, SplunkMode


class IngestorConfig(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", case_sensitive=False)

    # Top-level dispatcher. Splunk modes are still supported via SIEM_MODE=es|core.
    siem_mode: SIEMMode = SIEMMode.ES

    splunk_host: str = ""
    splunk_username: Optional[str] = None
    splunk_password: Optional[str] = None
    splunk_token: Optional[str] = None
    splunk_mode: SplunkMode = SplunkMode.ES
    splunk_verify_ssl: bool = False
    splunk_poll_interval_seconds: int = 30
    splunk_max_events_per_poll: int = 500
    splunk_es_status_filter: list[str] = ["new"]
    splunk_es_severity_filter: list[str] = ["critical", "high", "medium"]
    # SEARCH mode: poll a raw index directly (license-independent — no alerting).
    # The ingestor runs VIGIL's detection evaluator over the returned rows.
    splunk_search_index: str = "vigil_test"
    splunk_search_query: Optional[str] = None  # extra SPL after the index filter

    # Microsoft Sentinel.
    sentinel_tenant_id: Optional[str] = None
    sentinel_client_id: Optional[str] = None
    sentinel_client_secret: Optional[str] = None
    sentinel_subscription_id: Optional[str] = None
    sentinel_resource_group: Optional[str] = None
    sentinel_workspace_name: Optional[str] = None

    # Elastic.
    elastic_url: Optional[str] = None
    elastic_api_key_id: Optional[str] = None
    elastic_api_key_secret: Optional[str] = None
    elastic_verify_ssl: bool = True

    kafka_bootstrap_servers: str = "localhost:9092"
    kafka_topic_signals: str = "vigil.signals.raw"

    redis_url: str = "redis://localhost:6379/0"
    elasticsearch_url: str = "http://localhost:9200"

    port: int = 8001
    log_level: str = "INFO"
    tenant_id: str = "default"

    # Postgres DSN — only needed for the inbound POST /signals webhook, which
    # authenticates customer API keys against the shared api_keys table. The
    # poll-based ingest path does not require it, so it stays optional and the
    # pool is opened lazily on first authenticated request.
    database_url: Optional[str] = None

    # Shared JWT secret — lets the analyst UI authenticate to ingest/simulation
    # endpoints with a user session token (HS256), same as the other services.
    auth_secret: Optional[str] = None


_config: Optional[IngestorConfig] = None


def get_config() -> IngestorConfig:
    global _config
    if _config is None:
        _config = IngestorConfig()
    return _config
