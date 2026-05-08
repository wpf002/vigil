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
from uuid import UUID, uuid4

import httpx
import structlog
from kafka import KafkaConsumer
from kafka.errors import KafkaError, NoBrokersAvailable
from temporalio.client import Client as TemporalClient

from .config import PlaybookEngineConfig
from .narrative_loader import (
    Narrative,
    load_narratives,
    render_actions_for,
    select_playbook,
)
from .store import PlaybookStore
from .workflows.response_workflow import ResponseWorkflow, ResponseWorkflowInput

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
            attack_state = await self._fetch_attack_state(str(attack_id_str), str(tenant_id_str))
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

    async def _fetch_attack_state(self, attack_id: str, tenant_id: str) -> Optional[dict[str, Any]]:
        url = f"{self.cfg.attack_state_engine_url.rstrip('/')}/attacks/{attack_id}"
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(
                    url,
                    headers={
                        "X-Tenant-Id": tenant_id,
                    },
                )
                if resp.status_code != 200:
                    return None
                body = resp.json()
                if isinstance(body, dict) and "data" in body:
                    return body["data"] if isinstance(body["data"], dict) else None
                return body if isinstance(body, dict) else None
        except Exception as e:
            logger.warning("playbook_consumer.fetch_failed", error=str(e))
            return None

    async def _dispatch(self, attack_state: dict[str, Any]) -> None:
        attack_id = UUID(str(attack_state["attack_id"]))
        tenant_id_str = str(attack_state["tenant_id"])
        try:
            tenant_id = UUID(tenant_id_str)
        except (ValueError, TypeError):
            # Dev-mode tenants may be free-form strings; coerce deterministically.
            from uuid import uuid5, NAMESPACE_DNS
            tenant_id = uuid5(NAMESPACE_DNS, tenant_id_str)

        phase = str(attack_state.get("current_phase") or "")
        confidence = float(attack_state.get("confidence") or 0.0)

        # Pick status by reading the matching phase entry; default Observed.
        status = "Observed"
        for ph in attack_state.get("phases") or []:
            if isinstance(ph, dict) and str(ph.get("phase")) == phase:
                status = str(ph.get("status") or status)
                break

        playbook = select_playbook(
            self._narratives, phase=phase, status=status, confidence=confidence
        )
        if playbook is None:
            logger.info("playbook_consumer.no_playbook_match", phase=phase, status=status)
            return

        primary_host = next(iter(attack_state.get("hosts") or []), None)
        primary_user = next(iter(attack_state.get("users") or []), None)
        actions = render_actions_for(
            playbook, primary_host=primary_host, primary_user=primary_user
        )

        run_id = uuid4()
        workflow_id = f"playbook-{run_id}"

        await self.store.create_run(
            attack_id=attack_id,
            tenant_id=tenant_id,
            workflow_id=workflow_id,
            narrative_id=playbook.narrative_id,
            phase_at_trigger=phase,
            confidence_at_trigger=confidence,
            actions=actions,
        )

        await self.temporal_client.start_workflow(
            ResponseWorkflow.run,
            ResponseWorkflowInput(
                attack_id=str(attack_id),
                tenant_id=str(tenant_id),
                run_id=str(run_id),
                actions=actions,
                attack_state_engine_url=self.cfg.attack_state_engine_url,
                internal_api_key=self.cfg.internal_api_key,
            ),
            id=workflow_id,
            task_queue=self.cfg.temporal_task_queue,
        )

        logger.info(
            "playbook_consumer.dispatched",
            attack_id=str(attack_id),
            workflow_id=workflow_id,
            playbook=playbook.playbook_name,
            actions=len(actions),
        )
