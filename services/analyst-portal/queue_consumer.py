"""Kafka consumer that funnels escalations + paused playbooks into the queue.

Two topics:
  vigil.attacks.escalated     priority derived from impact + confidence
  vigil.playbooks.paused      always priority=critical (analyst must intervene)

If no SLA config exists for the tenant + tier, falls back to defaults from
config (sla_critical_minutes etc.).
"""

from __future__ import annotations
import asyncio
import json
from datetime import datetime, timezone
from typing import Any, Optional
from uuid import UUID, uuid5, NAMESPACE_DNS

import structlog
from kafka import KafkaConsumer
from kafka.errors import KafkaError, NoBrokersAvailable

from .config import AnalystPortalConfig
from .store import AnalystPortalStore, deadline_for

logger = structlog.get_logger(__name__)


def _tenant_to_uuid(raw: str) -> UUID:
    try:
        return UUID(raw)
    except (ValueError, TypeError):
        return uuid5(NAMESPACE_DNS, raw)


def derive_priority(state: dict[str, Any]) -> str:
    """Priority tier for escalation queue entries.

    Critical impact OR confidence>=0.85 → critical.
    High impact OR confidence>=0.70     → high.
    Else                                → medium.
    """
    impact = str(state.get("impact") or "").lower()
    confidence = float(state.get("confidence") or 0.0)
    if impact == "critical" or confidence >= 0.85:
        return "critical"
    if impact == "high" or confidence >= 0.70:
        return "high"
    return "medium"


async def resolve_response_minutes(
    store: AnalystPortalStore,
    cfg: AnalystPortalConfig,
    tenant_id: UUID,
    priority: str,
) -> int:
    sla = await store.get_sla_for(tenant_id, priority)
    if sla:
        return int(sla["response_minutes"])
    return {
        "critical": cfg.sla_critical_minutes,
        "high": cfg.sla_high_minutes,
        "medium": cfg.sla_medium_minutes,
        "low": cfg.sla_low_minutes,
    }.get(priority, cfg.sla_medium_minutes)


class QueueConsumer:
    def __init__(self, cfg: AnalystPortalConfig, store: AnalystPortalStore):
        self.cfg = cfg
        self.store = store
        self._consumer: Optional[KafkaConsumer] = None
        self._running = False
        self._processed = 0
        self._errors = 0

    @property
    def processed(self) -> int:
        return self._processed

    @property
    def errors(self) -> int:
        return self._errors

    def is_connected(self) -> bool:
        return self._consumer is not None

    def connect(self) -> None:
        try:
            self._consumer = KafkaConsumer(
                self.cfg.kafka_topic_attacks_escalated,
                self.cfg.kafka_topic_playbooks_paused,
                bootstrap_servers=self.cfg.kafka_bootstrap_servers.split(","),
                group_id=self.cfg.kafka_consumer_group,
                auto_offset_reset="latest",
                enable_auto_commit=False,
                value_deserializer=lambda v: json.loads(v.decode("utf-8")),
                key_deserializer=lambda k: k.decode("utf-8") if k else None,
                consumer_timeout_ms=1000,
                max_poll_records=20,
            )
            logger.info("queue_consumer.connected", group=self.cfg.kafka_consumer_group)
        except NoBrokersAvailable as e:
            logger.error("queue_consumer.no_brokers", error=str(e))
            raise

    def disconnect(self) -> None:
        if self._consumer is not None:
            self._consumer.close()
            self._consumer = None

    def stop(self) -> None:
        self._running = False

    async def run(self) -> None:
        if self._consumer is None:
            raise RuntimeError("Consumer not connected")
        self._running = True
        loop = asyncio.get_event_loop()

        while self._running:
            try:
                batch = await loop.run_in_executor(
                    None, lambda: self._consumer.poll(timeout_ms=1000, max_records=20)
                )
            except KafkaError as e:
                self._errors += 1
                logger.error("queue_consumer.poll_failed", error=str(e))
                await asyncio.sleep(2)
                continue

            if not batch:
                await asyncio.sleep(0.1)
                continue

            for tp, records in batch.items():
                for record in records:
                    await self._process_record(tp.topic, record)

            try:
                await loop.run_in_executor(None, self._consumer.commit)
            except KafkaError as e:
                logger.error("queue_consumer.commit_failed", error=str(e))

    async def _process_record(self, topic: str, record) -> None:
        try:
            payload = record.value or {}
            if topic == self.cfg.kafka_topic_attacks_escalated:
                await self._handle_escalation(payload)
            elif topic == self.cfg.kafka_topic_playbooks_paused:
                await self._handle_paused(payload)
            self._processed += 1
        except Exception as e:
            self._errors += 1
            logger.exception("queue_consumer.record_failed", topic=topic, error=str(e))

    async def _handle_escalation(self, payload: dict[str, Any]) -> None:
        state = payload.get("state") or payload
        if not isinstance(state, dict):
            return
        attack_id = state.get("attack_id")
        tenant_raw = state.get("tenant_id")
        if not attack_id or not tenant_raw:
            return

        priority = derive_priority(state)
        tenant_id = _tenant_to_uuid(str(tenant_raw))
        response_minutes = await resolve_response_minutes(
            self.store, self.cfg, tenant_id, priority
        )
        escalated_at = datetime.now(timezone.utc)
        sla_deadline = deadline_for(escalated_at, response_minutes)

        await self.store.enqueue_escalation(
            attack_id=UUID(str(attack_id)),
            tenant_id=tenant_id,
            priority=priority,
            sla_deadline=sla_deadline,
            escalated_at=escalated_at,
        )

    async def _handle_paused(self, payload: dict[str, Any]) -> None:
        attack_id = payload.get("attack_id")
        tenant_raw = payload.get("tenant_id")
        if not attack_id or not tenant_raw:
            return

        tenant_id = _tenant_to_uuid(str(tenant_raw))
        escalated_at = datetime.now(timezone.utc)
        # Paused playbooks always get the most aggressive SLA: 15 minutes.
        sla_deadline = deadline_for(escalated_at, self.cfg.sla_critical_minutes)
        await self.store.enqueue_escalation(
            attack_id=UUID(str(attack_id)),
            tenant_id=tenant_id,
            priority="critical",
            sla_deadline=sla_deadline,
            escalated_at=escalated_at,
            notes=f"Playbook paused: {payload.get('reason') or 'analyst intervention required'}",
        )
