"""
VIGIL Ingestor Service

Polls Splunk / Sentinel / Elastic, normalizes events to CDM,
publishes to vigil.signals.raw for the correlation engine.
"""

from __future__ import annotations
import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Optional
import structlog
import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from .config import IngestorConfig, get_config
from .connectors.elastic import ElasticConnector
from .connectors.sentinel import SentinelConnector
from .connectors.splunk_base import SplunkConnectionError, SplunkAuthError
from .connectors.splunk_core import SplunkCoreConnector
from .connectors.splunk_es import SplunkESConnector
from .models.cdm import CDMEvent, SIEMMode, SplunkMode
from .normalizer.normalizer import EventNormalizer
from .producer.kafka_producer import VIGILProducer

logger = structlog.get_logger(__name__)


SPLUNK_MODES = {SIEMMode.ES, SIEMMode.CORE, SIEMMode.HEC}


class IngestorEngine:
    def __init__(self, config: IngestorConfig):
        self.config = config
        self.normalizer = EventNormalizer()
        self.producer = VIGILProducer(
            bootstrap_servers=config.kafka_bootstrap_servers,
            topic_signals=config.kafka_topic_signals,
        )
        self._connector = None
        self._running = False
        self._last_poll: Optional[datetime] = None
        self._total_ingested: int = 0
        self._poll_errors: int = 0

    async def start(self) -> None:
        logger.info("ingestor.starting", siem_mode=self.config.siem_mode)
        self.producer.connect()
        self._connector = self._build_connector()
        await self._connector.connect()
        healthy = await self._connector.health_check()
        if not healthy:
            raise RuntimeError(f"{self.config.siem_mode} health check failed on startup")
        self._running = True
        await self._poll_loop()

    async def stop(self) -> None:
        self._running = False
        if self._connector:
            await self._connector.disconnect()
        self.producer.disconnect()

    async def _poll_loop(self) -> None:
        last_poll_time = datetime.now(timezone.utc) - timedelta(seconds=self.config.splunk_poll_interval_seconds)
        while self._running:
            poll_start = datetime.now(timezone.utc)
            try:
                events = await self._poll(last_poll_time, poll_start)
                if events:
                    published = await self.producer.publish_signals_batch(events)
                    self._total_ingested += published
                    logger.info("ingestor.cycle.complete", polled=len(events), published=published, total=self._total_ingested)
                last_poll_time = poll_start
                self._last_poll = poll_start
                self._poll_errors = 0
            except (SplunkConnectionError, SplunkAuthError) as e:
                self._poll_errors += 1
                logger.error("ingestor.poll.splunk_error", error=str(e), errors=self._poll_errors)
                backoff = min(self.config.splunk_poll_interval_seconds * (2 ** min(self._poll_errors, 5)), 300)
                await asyncio.sleep(backoff)
                continue
            except Exception as e:
                self._poll_errors += 1
                logger.exception("ingestor.poll.unexpected_error", error=str(e))
            await asyncio.sleep(self.config.splunk_poll_interval_seconds)

    async def _poll(self, since: datetime, until: datetime) -> list[CDMEvent]:
        mode = self.config.siem_mode

        if mode in SPLUNK_MODES:
            earliest = str(since.timestamp())
            latest = str(until.timestamp())
            if mode == SIEMMode.ES:
                raw = await self._connector.get_notable_events(
                    earliest=earliest, latest=latest,
                    status_filter=self.config.splunk_es_status_filter,
                    severity_filter=self.config.splunk_es_severity_filter,
                    max_events=self.config.splunk_max_events_per_poll,
                )
                return [self.normalizer.normalize_notable_event(e, self.config.tenant_id) for e in raw]
            if mode == SIEMMode.CORE:
                alerts = await self._connector.get_triggered_alerts(earliest=earliest, latest=latest)
                events = []
                for alert in alerts:
                    events.extend(self.normalizer.normalize_core_alert(alert, self.config.tenant_id))
                return events
            return []

        if mode == SIEMMode.SENTINEL:
            incidents = await self._connector.get_incidents(since=since)
            return [self._connector.map_incident(i, self.config.tenant_id) for i in incidents]

        if mode == SIEMMode.ELASTIC:
            hits = await self._connector.get_active_alerts(since=since)
            return [self._connector.map_alert(h, self.config.tenant_id) for h in hits]

        return []

    def _build_connector(self):
        mode = self.config.siem_mode
        cfg = self.config

        if mode in {SIEMMode.ES, SIEMMode.CORE, SIEMMode.HEC}:
            kwargs = dict(
                host=cfg.splunk_host,
                username=cfg.splunk_username,
                password=cfg.splunk_password,
                token=cfg.splunk_token,
                verify_ssl=cfg.splunk_verify_ssl,
                mode=SplunkMode(mode.value) if mode.value in {"es", "core", "hec"} else SplunkMode.ES,
            )
            return SplunkESConnector(**kwargs) if mode == SIEMMode.ES else SplunkCoreConnector(**kwargs)

        if mode == SIEMMode.SENTINEL:
            for k in (
                "sentinel_tenant_id", "sentinel_client_id", "sentinel_client_secret",
                "sentinel_subscription_id", "sentinel_resource_group", "sentinel_workspace_name",
            ):
                if not getattr(cfg, k):
                    raise RuntimeError(f"SIEM_MODE=sentinel requires {k.upper()}")
            return SentinelConnector(
                tenant_id=cfg.sentinel_tenant_id,
                client_id=cfg.sentinel_client_id,
                client_secret=cfg.sentinel_client_secret,
                subscription_id=cfg.sentinel_subscription_id,
                resource_group=cfg.sentinel_resource_group,
                workspace_name=cfg.sentinel_workspace_name,
            )

        if mode == SIEMMode.ELASTIC:
            for k in ("elastic_url", "elastic_api_key_id", "elastic_api_key_secret"):
                if not getattr(cfg, k):
                    raise RuntimeError(f"SIEM_MODE=elastic requires {k.upper()}")
            return ElasticConnector(
                url=cfg.elastic_url,
                api_key_id=cfg.elastic_api_key_id,
                api_key_secret=cfg.elastic_api_key_secret,
                verify_ssl=cfg.elastic_verify_ssl,
            )

        raise RuntimeError(f"Unsupported SIEM_MODE: {mode}")

    def get_status(self) -> dict:
        return {
            "running": self._running,
            "siem_mode": self.config.siem_mode,
            "splunk_host": self.config.splunk_host,
            "tenant_id": self.config.tenant_id,
            "last_poll": self._last_poll.isoformat() if self._last_poll else None,
            "total_ingested": self._total_ingested,
            "consecutive_errors": self._poll_errors,
            "kafka_connected": self.producer.is_connected(),
        }


engine: Optional[IngestorEngine] = None
_engine_task: Optional[asyncio.Task] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global engine, _engine_task
    config = get_config()
    engine = IngestorEngine(config)
    _engine_task = asyncio.create_task(engine.start())
    yield
    if engine:
        await engine.stop()
    if _engine_task:
        _engine_task.cancel()


app = FastAPI(title="VIGIL Ingestor", version="0.1.0", lifespan=lifespan)


@app.get("/health")
async def health():
    if not engine:
        return JSONResponse({"status": "starting"}, status_code=503)
    s = engine.get_status()
    ok = s["running"] and s["kafka_connected"]
    return JSONResponse({"status": "ok" if ok else "degraded", **s}, status_code=200 if ok else 503)


@app.get("/status")
async def status():
    if not engine:
        raise HTTPException(status_code=503, detail="Engine not initialized")
    return engine.get_status()


@app.post("/poll/trigger")
async def trigger_poll():
    if not engine or not engine._running:
        raise HTTPException(status_code=503, detail="Engine not running")
    now = datetime.now(timezone.utc)
    events = await engine._poll(now - timedelta(minutes=15), now)
    published = await engine.producer.publish_signals_batch(events) if events else 0
    return {"polled": len(events), "published": published, "timestamp": now.isoformat()}


if __name__ == "__main__":
    config = get_config()
    uvicorn.run("main:app", host="0.0.0.0", port=config.port, reload=False)
