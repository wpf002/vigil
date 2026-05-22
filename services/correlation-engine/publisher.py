"""Kafka publisher for AttackState lifecycle events."""

from __future__ import annotations

import asyncio
import json
from concurrent.futures import ThreadPoolExecutor
from typing import Optional
from uuid import UUID

import structlog
from kafka import KafkaProducer
from kafka.errors import KafkaError, NoBrokersAvailable

from ._compat import AttackState, AttackStateTransition

logger = structlog.get_logger(__name__)


def _json_default(obj):
    if isinstance(obj, UUID):
        return str(obj)
    raise TypeError(f"Not serializable: {type(obj)}")


class AttackPublisher:
    def __init__(
        self,
        bootstrap_servers: str,
        topic_created: str,
        topic_updated: str,
        topic_escalated: str,
        max_workers: int = 4,
    ):
        self.bootstrap_servers = bootstrap_servers
        self.topic_created = topic_created
        self.topic_updated = topic_updated
        self.topic_escalated = topic_escalated
        self._producer: Optional[KafkaProducer] = None
        self._executor = ThreadPoolExecutor(max_workers=max_workers)

    def connect(self) -> None:
        try:
            self._producer = KafkaProducer(
                bootstrap_servers=self.bootstrap_servers.split(","),
                value_serializer=lambda v: json.dumps(v, default=_json_default).encode("utf-8"),
                key_serializer=lambda k: k.encode("utf-8") if k else None,
                acks="all",
                retries=3,
                retry_backoff_ms=300,
                compression_type="gzip",
            )
            logger.info("attack_publisher.connected", servers=self.bootstrap_servers)
        except NoBrokersAvailable as e:
            logger.error("attack_publisher.no_brokers", error=str(e))
            raise

    def disconnect(self) -> None:
        if self._producer:
            self._producer.flush(timeout=5)
            self._producer.close(timeout=5)
            self._producer = None

    def is_connected(self) -> bool:
        return self._producer is not None

    async def publish_attack_created(self, state: AttackState) -> bool:
        return await self._publish(self.topic_created, state.tenant_id, state.model_dump(mode="json"))

    async def publish_attack_updated(
        self, state: AttackState, transition: AttackStateTransition
    ) -> bool:
        payload = {
            "state": state.model_dump(mode="json"),
            "transition": transition.model_dump(mode="json"),
        }
        return await self._publish(self.topic_updated, state.tenant_id, payload)

    async def publish_attack_escalated(
        self, state: AttackState, transition: AttackStateTransition
    ) -> bool:
        payload = {
            "state": state.model_dump(mode="json"),
            "transition": transition.model_dump(mode="json"),
        }
        return await self._publish(self.topic_escalated, state.tenant_id, payload)

    async def _publish(self, topic: str, key: str, value: dict) -> bool:
        if not self._producer:
            raise RuntimeError("Publisher not connected")
        loop = asyncio.get_event_loop()
        try:
            await loop.run_in_executor(
                self._executor,
                lambda: self._producer.send(topic=topic, key=key, value=value).get(timeout=10),
            )
            return True
        except KafkaError as e:
            logger.error("attack_publisher.publish_failed", topic=topic, error=str(e))
            return False
