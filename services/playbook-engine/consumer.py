"""Kafka consumer — vigil.attacks.escalated.

For each escalation: load the AttackState from attack-state-engine, match
a response playbook from the narratives library, persist a playbook_runs
row, and start a Temporal ResponseWorkflow.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, Optional

import structlog
from kafka import KafkaConsumer
from kafka.errors import KafkaError, NoBrokersAvailable
from temporalio.client import Client as TemporalClient

from .config import PlaybookEngineConfig
from .dispatcher import dispatch_playbook, fetch_attack_state
from .narrative_loader import Narrative, load_narratives
from .store import PlaybookStore

logger = structlog.get_logger(__name__)


class EscalationConsumer:
    def __init__(
        self,
        cfg: PlaybookEngineConfig,
        store: PlaybookStore,
        temporal_client: TemporalClient,
    ):
        self.cfg = cfg
        self.store = store
        self.temporal_client = temporal_client
        self._consumer: Optional[KafkaConsumer] = None
        self._running = False
        self._processed = 0
        self._errors = 0
        self._narratives: list[Narrative] = []

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
                bootstrap_servers=self.cfg.kafka_bootstrap_servers.split(","),
                group_id=self.cfg.kafka_consumer_group,
                auto_offset_reset="latest",
                enable_auto_commit=False,
                value_deserializer=lambda v: json.loads(v.decode("utf-8")),
                key_deserializer=lambda k: k.decode("utf-8") if k else None,
                consumer_timeout_ms=1000,
                max_poll_records=10,
            )
            logger.info(
                "playbook_consumer.connected",
                topic=self.cfg.kafka_topic_attacks_escalated,
                group=self.cfg.kafka_consumer_group,
            )
        except NoBrokersAvailable as e:
            logger.error("playbook_consumer.no_brokers", error=str(e))
            raise

        # Pre-load narratives now so dispatch is cheap.
        self._narratives = load_narratives(Path(self.cfg.narratives_path))
        logger.info("playbook_consumer.narratives_loaded", count=len(self._narratives))

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
                    None, lambda: self._consumer.poll(timeout_ms=1000, max_records=10)
                )
            except KafkaError as e:
                self._errors += 1
                logger.error("playbook_consumer.poll_failed", error=str(e))
                await asyncio.sleep(2)
                continue

            if not batch:
                await asyncio.sleep(0.1)
                continue

            for tp, records in batch.items():
                for record in records:
                    await self._process_record(record)

            try:
                await loop.run_in_executor(None, self._consumer.commit)
            except KafkaError as e:
                logger.error("playbook_consumer.commit_failed", error=str(e))

    async def _process_record(self, record) -> None:
        payload = record.value
        if not isinstance(payload, dict):
            self._errors += 1
            logger.warning("playbook_consumer.bad_payload")
            return

        # Escalation events emit { "state": AttackState, "transition": ... }.
        # Be permissive about shape since publisher may serialize either.
        state = payload.get("state") or payload
        if not isinstance(state, dict):
            return

        attack_id_str = state.get("attack_id")
        tenant_id_str = state.get("tenant_id")
        if not attack_id_str or not tenant_id_str:
            self._errors += 1
            logger.warning("playbook_consumer.missing_ids")
            return

        try:
            attack_state = await fetch_attack_state(
                self.cfg, str(attack_id_str), str(tenant_id_str)
            )
            if attack_state is None:
                attack_state = state
            await self._dispatch(attack_state)
            self._processed += 1
        except Exception as e:
            self._errors += 1
            logger.exception(
                "playbook_consumer.dispatch_failed",
                attack_id=attack_id_str,
                error=str(e),
            )

    async def _dispatch(self, attack_state: dict[str, Any]) -> None:
        await dispatch_playbook(
            attack_state,
            narratives=self._narratives,
            store=self.store,
            temporal_client=self.temporal_client,
            cfg=self.cfg,
            trigger="auto",
        )

        logger.info(
            "playbook_consumer.dispatched",
            attack_id=str(attack_id),
            workflow_id=workflow_id,
            playbook=playbook.playbook_name,
            actions=len(actions),
        )
