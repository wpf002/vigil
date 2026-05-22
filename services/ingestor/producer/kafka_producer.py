"""Kafka producer — publishes CDM events to vigil.signals.raw."""

from __future__ import annotations

import asyncio
import json
from concurrent.futures import ThreadPoolExecutor
from typing import Optional
from uuid import UUID

import structlog
from kafka import KafkaProducer
from kafka.errors import KafkaError, NoBrokersAvailable

from ..models.cdm import CDMEvent

logger = structlog.get_logger(__name__)


class VIGILProducer:
    def __init__(
        self,
        bootstrap_servers: str,
        topic_signals: str = "vigil.signals.raw",
        max_workers: int = 4,
    ):
        self.bootstrap_servers = bootstrap_servers
        self.topic_signals = topic_signals
        self._producer: Optional[KafkaProducer] = None
        self._executor = ThreadPoolExecutor(max_workers=max_workers)

    def connect(self) -> None:
        try:
            self._producer = KafkaProducer(
                bootstrap_servers=self.bootstrap_servers.split(","),
                value_serializer=lambda v: json.dumps(v, default=self._json_serial).encode("utf-8"),
                key_serializer=lambda k: k.encode("utf-8") if k else None,
                acks="all",
                retries=3,
                retry_backoff_ms=300,
                compression_type="gzip",
            )
            logger.info("kafka.producer.connected", servers=self.bootstrap_servers)
        except NoBrokersAvailable as e:
            logger.error("kafka.producer.no_brokers", error=str(e))
            raise

    def disconnect(self) -> None:
        if self._producer:
            self._producer.flush(timeout=5)
            self._producer.close(timeout=5)
            self._producer = None

    async def publish_signal(self, event: CDMEvent) -> bool:
        return await self._publish(self.topic_signals, event.tenant_id, event.model_dump(mode="json"))

    async def publish_signals_batch(self, events: list[CDMEvent]) -> int:
        results = await asyncio.gather(*[self.publish_signal(e) for e in events], return_exceptions=True)
        return sum(1 for r in results if r is True)

    async def _publish(self, topic: str, key: str, value: dict) -> bool:
        if not self._producer:
            raise RuntimeError("Producer not connected.")
        loop = asyncio.get_event_loop()
        try:
            await loop.run_in_executor(
                self._executor,
                lambda: self._producer.send(topic=topic, key=key, value=value).get(timeout=10),
            )
            return True
        except KafkaError as e:
            logger.error("kafka.publish_failed", topic=topic, error=str(e))
            return False

    def is_connected(self) -> bool:
        return self._producer is not None

    @staticmethod
    def _json_serial(obj):
        if isinstance(obj, UUID):
            return str(obj)
        raise TypeError(f"Not serializable: {type(obj)}")
