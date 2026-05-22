"""Webhook dispatcher.

Consumes Kafka topics in the vigil.attacks.* and vigil.playbooks.* family
and fans each event out to all active webhooks for the relevant tenant.
HMAC-SHA256 signs the body with the webhook's secret. Records success +
failure counts so the customer-facing stats stay accurate; auto-deactivates
webhooks at 10 consecutive failures.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from typing import Any, Optional
from uuid import UUID

import httpx
import structlog

from .key_store import KeyStore, hmac_sign

logger = structlog.get_logger(__name__)


KAFKA_TOPIC_TO_EVENT = {
    "vigil.attacks.created": "attack.created",
    "vigil.attacks.updated": "attack.updated",
    "vigil.attacks.escalated": "attack.escalated",
    "vigil.attacks.resolved": "attack.resolved",
    "vigil.playbooks.paused": "playbook.paused",
}


class WebhookDispatcher:
    """Kafka consumer that fans Kafka events out to customer webhooks."""

    def __init__(
        self,
        *,
        key_store: KeyStore,
        kafka_bootstrap_servers: str,
        consumer_group: str = "vigil-webhook-dispatcher",
        topics: Optional[list[str]] = None,
    ):
        self.key_store = key_store
        self.kafka_bootstrap_servers = kafka_bootstrap_servers
        self.consumer_group = consumer_group
        self.topics = topics or list(KAFKA_TOPIC_TO_EVENT.keys())
        self._consumer = None
        self._running = False

    def connect(self) -> None:
        from kafka import KafkaConsumer  # type: ignore

        self._consumer = KafkaConsumer(
            *self.topics,
            bootstrap_servers=self.kafka_bootstrap_servers,
            group_id=self.consumer_group,
            value_deserializer=lambda b: json.loads(b.decode("utf-8")),
            enable_auto_commit=True,
            auto_offset_reset="latest",
        )
        logger.info("webhook_dispatcher.connected", topics=self.topics)

    def disconnect(self) -> None:
        if self._consumer is not None:
            try:
                self._consumer.close()
            except Exception:
                pass
            self._consumer = None

    def stop(self) -> None:
        self._running = False

    async def run(self) -> None:
        if self._consumer is None:
            return
        self._running = True
        loop = asyncio.get_event_loop()

        def _poll():
            return self._consumer.poll(timeout_ms=1000)

        while self._running:
            try:
                batches = await loop.run_in_executor(None, _poll)
            except Exception as e:
                logger.warning("webhook_dispatcher.poll_failed", error=str(e))
                await asyncio.sleep(2)
                continue
            if not batches:
                continue
            for tp, records in batches.items():
                topic = tp.topic
                event_name = KAFKA_TOPIC_TO_EVENT.get(topic)
                if not event_name:
                    continue
                for rec in records:
                    try:
                        await self._dispatch(event_name, rec.value)
                    except Exception as e:
                        logger.warning("webhook_dispatcher.dispatch_failed", error=str(e))

    async def _dispatch(self, event: str, payload: dict[str, Any]) -> None:
        tenant_id = payload.get("tenant_id")
        if not tenant_id:
            return
        try:
            tenant_uuid = UUID(str(tenant_id))
        except (ValueError, TypeError):
            return

        webhooks = await self.key_store.list_active_webhooks_for_event(
            tenant_id=tenant_uuid, event=event,
        )
        if not webhooks:
            return

        body = {
            "event": event,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tenant_id": str(tenant_id),
            "data": payload,
        }
        body_bytes = json.dumps(body).encode("utf-8")

        async with httpx.AsyncClient(timeout=10.0) as client:
            for wh in webhooks:
                await self._deliver(client, wh, event, body_bytes)

    async def _deliver(self, client: httpx.AsyncClient, wh, event: str, body: bytes) -> None:
        sig = hmac_sign(wh.secret, body)
        headers = {
            "Content-Type": "application/json",
            "X-VIGIL-Event": event,
            "X-VIGIL-Signature": f"sha256={sig}",
        }

        attempt = 0
        delay = 0.5
        while attempt < 3:
            attempt += 1
            try:
                resp = await client.post(wh.url, content=body, headers=headers)
                if resp.status_code < 400:
                    await self.key_store.record_webhook_success(
                        wh.webhook_id, datetime.now(timezone.utc)
                    )
                    return
                logger.warning(
                    "webhook_dispatcher.bad_status",
                    webhook_id=str(wh.webhook_id),
                    status=resp.status_code, attempt=attempt,
                )
            except Exception as e:
                logger.warning(
                    "webhook_dispatcher.delivery_error",
                    webhook_id=str(wh.webhook_id),
                    error=str(e), attempt=attempt,
                )
            await asyncio.sleep(delay)
            delay *= 2

        count = await self.key_store.record_webhook_failure(wh.webhook_id)
        if count >= 10:
            logger.warning(
                "webhook_dispatcher.auto_disabled",
                webhook_id=str(wh.webhook_id), failure_count=count,
            )
