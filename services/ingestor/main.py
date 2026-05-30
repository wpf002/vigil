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
from uuid import uuid4

import structlog
import uvicorn
from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from . import simulation
from .auth import authenticate, close_pool
from .cdm_rules import DEFAULT_RULES, apply_match, best_match
from .config import IngestorConfig, get_config
from .connectors.demo import DemoConnector
from .connectors.elastic import ElasticConnector
from .connectors.sentinel import SentinelConnector
from .connectors.splunk_base import SplunkAuthError, SplunkConnectionError
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
        """Boot the ingest loop. SIEM unreachable / unconfigured leaves the
        engine in a degraded-but-running state so the FastAPI /health endpoint
        keeps responding — useful for local dev where Splunk isn't available."""
        logger.info("ingestor.starting", siem_mode=self.config.siem_mode)
        try:
            self.producer.connect()
        except Exception as e:
            logger.warning("ingestor.kafka_unavailable", error=str(e))

        try:
            self._connector = self._build_connector()
            await self._connector.connect()
            healthy = await self._connector.health_check()
        except Exception as e:
            logger.warning("ingestor.connector_init_failed", error=str(e))
            healthy = False

        if not healthy:
            logger.warning(
                "ingestor.degraded",
                siem_mode=self.config.siem_mode,
                detail="SIEM not reachable — entering degraded mode (no polling)",
            )
            # Park: keep the process alive so /health and /status respond.
            self._running = False
            return

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

        if mode == SIEMMode.DEMO:
            return await self._connector.get_events_since(since=since, tenant_id=self.config.tenant_id)

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

        if mode == SIEMMode.DEMO:
            return DemoConnector(batch_size=1)

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
    await close_pool()


app = FastAPI(title="VIGIL Ingestor", version="0.1.0", lifespan=lifespan)


@app.get("/health")
async def health():
    """Three-state health:
      ok          — actively polling a configured SIEM, Kafka connected
      not_configured — running but no SIEM credentials supplied (fresh dev)
      degraded    — running but Kafka unavailable / SIEM unreachable
    All three return 200 so the pipeline aggregator surfaces the state
    distinctly without flagging the service as 'unreachable'.
    """
    base = {"service": "ingestor", "version": "0.1.0"}
    if not engine:
        return JSONResponse({**base, "status": "starting"}, status_code=503)
    s = engine.get_status()
    siem_configured = (
        engine.config.siem_mode == SIEMMode.DEMO
        or bool(engine.config.splunk_host or engine.config.sentinel_tenant_id or engine.config.elastic_url)
    )
    if s["running"] and s["kafka_connected"]:
        status = "ok"
    elif not siem_configured:
        status = "not_configured"
    else:
        status = "degraded"
    return JSONResponse({**base, "status": status, **s}, status_code=200)


@app.get("/status")
async def status():
    if not engine:
        raise HTTPException(status_code=503, detail="Engine not initialized")
    return engine.get_status()


@app.post("/signals")
async def ingest_signal(event: CDMEvent, authorization: str = Header(default="")):
    """Agent-less ingestion: accept a single CDM event and publish it straight
    to vigil.signals.raw, the same topic the SIEM pollers feed.

    Auth is a Bearer `vgl_…` API key; the event is scoped to that key's tenant
    (the body's tenant_id is overwritten, never trusted). This is the inbound
    path the SDK's submit_signal() targets, and the seam for webhook-based
    ingestion, detection testing, and attack simulation.
    """
    tenant_id = await authenticate(authorization)
    if not engine or not engine.producer.is_connected():
        raise HTTPException(status_code=503, detail="ingest pipeline unavailable")
    event.tenant_id = tenant_id

    # In-transit detection: if the caller sent a raw event with no detection_id,
    # run the CDM rule evaluator and tag it with the best matching detection so
    # it flows into correlation. Events that already carry a detection_id (e.g.
    # SIEM-sourced) are passed through untouched.
    matched = None
    if not event.detection_id:
        rule = best_match(event, DEFAULT_RULES)
        if rule:
            apply_match(event, rule)
            matched = rule.detection_id

    published = await engine.producer.publish_signal(event)
    if not published:
        raise HTTPException(status_code=502, detail="failed to publish signal")
    return {
        "event_id": str(event.event_id),
        "tenant_id": tenant_id,
        "detection_id": event.detection_id,
        "matched_rule": matched,
        "published": True,
    }


class SimulationRunRequest(BaseModel):
    scenario_id: str
    host: Optional[str] = None
    user: Optional[str] = None


@app.get("/simulations/scenarios")
async def list_simulations(authorization: str = Header(default="")):
    """Catalog of agent-less purple-team scenarios."""
    await authenticate(authorization)
    return {"scenarios": simulation.list_scenarios()}


@app.post("/simulations/run")
async def run_simulation(body: SimulationRunRequest, authorization: str = Header(default="")):
    """Inject a synthetic ATT&CK kill-chain into the pipeline for the caller's
    tenant. The events flow through correlation and create a real attack —
    no in-environment agent required.
    """
    tenant_id = await authenticate(authorization)
    scenario = simulation.get_scenario(body.scenario_id)
    if scenario is None:
        raise HTTPException(status_code=404, detail=f"unknown scenario '{body.scenario_id}'")
    if not engine or not engine.producer.is_connected():
        raise HTTPException(status_code=503, detail="ingest pipeline unavailable")

    events = simulation.build_events(
        scenario, tenant_id,
        host=body.host or "SIM-HOST-01",
        user=body.user or "sim_user",
    )
    published = await engine.producer.publish_signals_batch(events)
    return {
        "simulation_id": uuid4().hex,
        "scenario": scenario["id"],
        "scenario_name": scenario["name"],
        "tenant_id": tenant_id,
        "emitted": len(events),
        "published": published,
        "expected_detections": [s[0] for s in scenario["steps"]],
        "expected_phases": sorted({s[3] for s in scenario["steps"]}),
    }


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
