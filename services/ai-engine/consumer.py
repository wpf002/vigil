"""Kafka consumer for attack lifecycle events.

Subscribes to vigil.attacks.{created,updated} and dispatches each payload
to the narrator. Handles cache lookups, API errors, and PATCH writes.
"""

from __future__ import annotations
import asyncio
import json
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Optional

import httpx
import structlog
from kafka import KafkaConsumer
from kafka.errors import KafkaError, NoBrokersAvailable

from .cache import NarrativeCache
from .narrator import Narrator, NarrativeResult

logger = structlog.get_logger(__name__)


class NarrativeConsumer:
    def __init__(
        self,
        *,
        bootstrap_servers: str,
        topics: list[str],
        group_id: str,
        narrator: Narrator,
        cache: NarrativeCache,
        attack_state_url: str,
        internal_api_key: str,
        confidence_delta_skip: float = 0.05,
    ):
        self.bootstrap_servers = bootstrap_servers
        self.topics = topics
        self.group_id = group_id
        self._narrator = narrator
        self._cache = cache
        self._attack_state_url = attack_state_url.rstrip("/")
        self._internal_api_key = internal_api_key
        self._confidence_delta_skip = confidence_delta_skip

        self._consumer: Optional[KafkaConsumer] = None
        self._stop = False
        self.processed = 0
        self.errors = 0
        self._executor = ThreadPoolExecutor(max_workers=2)

    def connect(self) -> None:
        try:
            self._consumer = KafkaConsumer(
                *self.topics,
                bootstrap_servers=self.bootstrap_servers.split(","),
                group_id=self.group_id,
                value_deserializer=lambda v: json.loads(v.decode("utf-8")),
                auto_offset_reset="latest",
                enable_auto_commit=True,
            )
            logger.info("ai_engine.consumer.connected", topics=self.topics)
        except NoBrokersAvailable as e:
            logger.error("ai_engine.consumer.no_brokers", error=str(e))
            raise

    def disconnect(self) -> None:
        if self._consumer:
            try:
                self._consumer.close(autocommit=True)
            except Exception:
                pass
            self._consumer = None

    def is_connected(self) -> bool:
        return self._consumer is not None

    def stop(self) -> None:
        self._stop = True

    async def run(self) -> None:
        """Main loop. Polls Kafka in a thread, dispatches messages async."""
        if self._consumer is None:
            raise RuntimeError("Consumer not connected")
        loop = asyncio.get_event_loop()
        while not self._stop:
            batch = await loop.run_in_executor(self._executor, self._poll_once)
            if not batch:
                await asyncio.sleep(0.1)
                continue
            for msg in batch:
                try:
                    await self._handle(msg.value)
                    self.processed += 1
                except Exception as e:
                    self.errors += 1
                    logger.exception("ai_engine.consumer.handler_error", error=str(e))

    def _poll_once(self):
        if self._consumer is None:
            return []
        polled = self._consumer.poll(timeout_ms=500)
        flat = []
        for _tp, msgs in polled.items():
            flat.extend(msgs)
        return flat

    async def _handle(self, payload: dict[str, Any]) -> None:
        # vigil.attacks.created publishes the AttackState directly.
        # vigil.attacks.updated wraps it in {state, transition}.
        state = payload.get("state") if isinstance(payload, dict) and "state" in payload else payload
        if not isinstance(state, dict) or not state.get("attack_id"):
            logger.warning("ai_engine.consumer.bad_payload")
            return

        attack_id = str(state["attack_id"])
        confidence = float(state.get("confidence") or 0.0)

        # Cache: skip if a near-confidence narrative was generated recently.
        latest = await self._cache.latest_confidence(attack_id)
        if latest is not None and abs(latest - confidence) < self._confidence_delta_skip:
            logger.info(
                "ai_engine.consumer.skipped_close_confidence",
                attack_id=attack_id,
                latest=latest,
                current=confidence,
            )
            return

        result = await self._call_narrator(state)
        if result is None:
            return

        await self._patch_state(attack_id, result)
        await self._cache.set(attack_id, confidence, result.to_patch_body())

    async def _call_narrator(self, state: dict[str, Any]) -> Optional[NarrativeResult]:
        loop = asyncio.get_event_loop()
        try:
            return await loop.run_in_executor(
                self._executor, self._narrator.generate, state
            )
        except Exception as e:
            logger.warning(
                "ai_engine.narrator.failed",
                attack_id=state.get("attack_id"),
                error_type=type(e).__name__,
            )
            return None

    async def _patch_state(self, attack_id: str, result: NarrativeResult) -> None:
        url = f"{self._attack_state_url}/attacks/{attack_id}/narrative"
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.patch(
                    url,
                    headers={"X-Internal-Key": self._internal_api_key},
                    json=result.to_patch_body(),
                )
                if resp.status_code >= 400:
                    logger.warning(
                        "ai_engine.patch.failed",
                        attack_id=attack_id,
                        status=resp.status_code,
                    )
                else:
                    logger.info("ai_engine.patch.ok", attack_id=attack_id)
        except httpx.HTTPError as e:
            logger.warning(
                "ai_engine.patch.transport_failed",
                attack_id=attack_id,
                error=str(e),
            )


# Convenience factory for main.py.

def build_consumer(
    *, narrator: Narrator, cache: NarrativeCache, cfg
) -> NarrativeConsumer:
    return NarrativeConsumer(
        bootstrap_servers=cfg.kafka_bootstrap_servers,
        topics=[cfg.kafka_topic_attacks_created, cfg.kafka_topic_attacks_updated],
        group_id=cfg.kafka_consumer_group,
        narrator=narrator,
        cache=cache,
        attack_state_url=cfg.attack_state_engine_url,
        internal_api_key=cfg.internal_api_key,
    )
