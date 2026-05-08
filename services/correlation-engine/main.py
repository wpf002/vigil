"""
VIGIL Correlation Engine

Consumes CDMEvents from vigil.signals.raw, updates AttackState,
publishes to vigil.attacks.{created,updated,escalated}.
"""

from __future__ import annotations
import asyncio
from contextlib import asynccontextmanager
from typing import Optional

import structlog
import uvicorn
from fastapi import FastAPI
from fastapi.responses import JSONResponse

from ._compat import AttackStateStore
from .config import CorrelationConfig, get_config
from .consumer import SignalConsumer
from .detection_engine_client import DetectionEngineClient
from .entity_index import EntityIndex
from .handlers.signal_handler import SignalHandler
from .publisher import AttackPublisher

logger = structlog.get_logger(__name__)


class CorrelationEngine:
    def __init__(self, config: CorrelationConfig):
        self.config = config
        self.store: Optional[AttackStateStore] = None
        self.entity_index: Optional[EntityIndex] = None
        self.publisher: Optional[AttackPublisher] = None
        self.consumer: Optional[SignalConsumer] = None
        self.detection_engine: Optional[DetectionEngineClient] = None
        self._consumer_task: Optional[asyncio.Task] = None

    async def start(self) -> None:
        logger.info("correlation_engine.starting")

        self.store = await AttackStateStore.from_dsn(self.config.database_url)

        self.entity_index = await EntityIndex.from_url(
            self.config.redis_url,
            entity_ttl_seconds=self.config.entity_index_ttl_seconds,
            idempotency_ttl_seconds=self.config.idempotency_ttl_seconds,
            lock_ttl_seconds=self.config.lock_ttl_seconds,
        )

        self.publisher = AttackPublisher(
            bootstrap_servers=self.config.kafka_bootstrap_servers,
            topic_created=self.config.kafka_topic_attacks_created,
            topic_updated=self.config.kafka_topic_attacks_updated,
            topic_escalated=self.config.kafka_topic_attacks_escalated,
        )
        self.publisher.connect()

        self.detection_engine = DetectionEngineClient(
            base_url=self.config.detection_engine_url,
            internal_key=self.config.internal_api_key,
        )

        handler = SignalHandler(
            store=self.store,
            entity_index=self.entity_index,
            publisher=self.publisher,
            detection_engine_client=self.detection_engine,
        )

        self.consumer = SignalConsumer(
            bootstrap_servers=self.config.kafka_bootstrap_servers,
            topic=self.config.kafka_topic_signals,
            group_id=self.config.kafka_consumer_group,
            handler=handler,
        )
        self.consumer.connect()
        self._consumer_task = asyncio.create_task(self.consumer.run())
        logger.info("correlation_engine.started")

    async def stop(self) -> None:
        if self.consumer:
            self.consumer.stop()
            self.consumer.disconnect()
        if self._consumer_task:
            self._consumer_task.cancel()
            try:
                await self._consumer_task
            except (asyncio.CancelledError, Exception):
                pass
        if self.publisher:
            self.publisher.disconnect()
        if self.detection_engine:
            await self.detection_engine.close()
        if self.entity_index:
            await self.entity_index.close()
        if self.store:
            await self.store.close()

    def get_status(self) -> dict:
        return {
            "running": bool(self._consumer_task and not self._consumer_task.done()),
            "kafka_consumer_connected": self.consumer.is_connected() if self.consumer else False,
            "kafka_publisher_connected": self.publisher.is_connected() if self.publisher else False,
            "processed_signals": self.consumer.processed_count if self.consumer else 0,
            "errors": self.consumer.error_count if self.consumer else 0,
            "topic": self.config.kafka_topic_signals,
            "consumer_group": self.config.kafka_consumer_group,
        }


engine: Optional[CorrelationEngine] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global engine
    config = get_config()
    engine = CorrelationEngine(config)
    await engine.start()
    yield
    if engine:
        await engine.stop()


app = FastAPI(title="VIGIL Correlation Engine", version="0.1.0", lifespan=lifespan)


@app.get("/health")
async def health():
    if engine is None:
        return JSONResponse({"status": "starting"}, status_code=503)
    s = engine.get_status()
    ok = s["running"] and s["kafka_consumer_connected"] and s["kafka_publisher_connected"]
    return JSONResponse(
        {"status": "ok" if ok else "degraded", **s},
        status_code=200 if ok else 503,
    )


@app.get("/status")
async def status():
    if engine is None:
        return JSONResponse({"status": "not_initialized"}, status_code=503)
    return engine.get_status()


if __name__ == "__main__":
    cfg = get_config()
    uvicorn.run(
        "services.correlation_engine.main:app",
        host="0.0.0.0",
        port=cfg.port,
        reload=False,
    )
