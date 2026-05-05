"""
Kafka consumer for vigil.signals.raw.

Deserializes each message into a CDMEvent, routes it to the SignalHandler,
and commits offsets only after successful processing. Failed events are
logged but skipped to avoid head-of-line blocking; idempotency in Redis
guarantees the SignalHandler is safe to retry.
"""

from __future__ import annotations
import asyncio
import json
from typing import Optional

import structlog
from kafka import KafkaConsumer
from kafka.errors import KafkaError, NoBrokersAvailable

from ._compat import CDMEvent
from .handlers.signal_handler import SignalHandler

logger = structlog.get_logger(__name__)


class SignalConsumer:
    def __init__(
        self,
        bootstrap_servers: str,
        topic: str,
        group_id: str,
        handler: SignalHandler,
    ):
        self.bootstrap_servers = bootstrap_servers
        self.topic = topic
        self.group_id = group_id
        self.handler = handler
        self._consumer: Optional[KafkaConsumer] = None
        self._running = False
        self._processed_count = 0
        self._error_count = 0

    def connect(self) -> None:
        try:
            self._consumer = KafkaConsumer(
                self.topic,
                bootstrap_servers=self.bootstrap_servers.split(","),
                group_id=self.group_id,
                auto_offset_reset="latest",
                enable_auto_commit=False,
                value_deserializer=lambda v: json.loads(v.decode("utf-8")),
                key_deserializer=lambda k: k.decode("utf-8") if k else None,
                consumer_timeout_ms=1000,
                max_poll_records=50,
            )
            logger.info("signal_consumer.connected", topic=self.topic, group=self.group_id)
        except NoBrokersAvailable as e:
            logger.error("signal_consumer.no_brokers", error=str(e))
            raise

    def disconnect(self) -> None:
        if self._consumer:
            self._consumer.close()
            self._consumer = None

    def is_connected(self) -> bool:
        return self._consumer is not None

    @property
    def processed_count(self) -> int:
        return self._processed_count

    @property
    def error_count(self) -> int:
        return self._error_count

    async def run(self) -> None:
        if not self._consumer:
            raise RuntimeError("Consumer not connected")
        self._running = True
        loop = asyncio.get_event_loop()

        while self._running:
            try:
                # KafkaConsumer poll is blocking — push to a thread.
                batch = await loop.run_in_executor(
                    None, lambda: self._consumer.poll(timeout_ms=1000, max_records=50)
                )
            except KafkaError as e:
                self._error_count += 1
                logger.error("signal_consumer.poll_failed", error=str(e))
                await asyncio.sleep(2)
                continue

            if not batch:
                # No records this poll cycle — yield.
                await asyncio.sleep(0.1)
                continue

            for tp, records in batch.items():
                for record in records:
                    await self._process_record(record)

            try:
                await loop.run_in_executor(None, self._consumer.commit)
            except KafkaError as e:
                logger.error("signal_consumer.commit_failed", error=str(e))

    async def _process_record(self, record) -> None:
        try:
            event = CDMEvent.model_validate(record.value)
        except Exception as e:
            self._error_count += 1
            logger.exception("signal_consumer.bad_event", error=str(e))
            return

        try:
            await self.handler.handle(event)
            self._processed_count += 1
        except Exception as e:
            self._error_count += 1
            logger.exception(
                "signal_consumer.handler_failed",
                event_id=str(event.event_id),
                error=str(e),
            )

    def stop(self) -> None:
        self._running = False
