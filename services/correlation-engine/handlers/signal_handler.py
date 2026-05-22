"""
SignalHandler — core correlation logic.

For each CDMEvent:
  1. Idempotency: skip if event_id already processed.
  2. Extract entities (host, user, process).
  3. Determine state impact (phase, status, contribution) from the detection registry
     or the embedded state_impact on the event.
  4. Look up an existing active AttackState for any matched entity (Redis first,
     fall back to PostgreSQL).
  5. Inside a tenant+entity-scoped Redis lock:
        - Re-check for an existing AttackState.
        - If found: append EvidenceItem, update entities/phases, recalc confidence,
          persist, publish to vigil.attacks.updated. If confidence crossed 0.70,
          publish to vigil.attacks.escalated.
        - If not: create a new AttackState seeded with the first EvidenceItem,
          persist, bind entities in Redis, publish to vigil.attacks.created.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional, Protocol
from uuid import UUID, uuid4

import structlog

from .. import detections_registry
from .._compat import (
    ESCALATION_THRESHOLD,
    AttackState,
    AttackStateStatus,
    AttackStateStore,
    AttackStateTransition,
    CDMEvent,
    ConfidenceEngine,
    EvidenceItem,
    MITRETactic,
    PhaseState,
    PhaseStatus,
)
from ..detection_engine_client import DetectionEngineClient
from ..entity_index import EntityIndex

logger = structlog.get_logger(__name__)


# Phase color/severity hints used to render attack names; not authoritative.
_PHASE_LABEL_FALLBACK = "Unclassified Activity"


class Publisher(Protocol):
    async def publish_attack_created(self, state: AttackState) -> bool: ...
    async def publish_attack_updated(self, state: AttackState, transition: AttackStateTransition) -> bool: ...
    async def publish_attack_escalated(self, state: AttackState, transition: AttackStateTransition) -> bool: ...


class SignalHandler:
    def __init__(
        self,
        store: AttackStateStore,
        entity_index: EntityIndex,
        publisher: Publisher,
        confidence_engine: Optional[ConfidenceEngine] = None,
        detection_engine_client: Optional[DetectionEngineClient] = None,
    ):
        self.store = store
        self.entity_index = entity_index
        self.publisher = publisher
        self.confidence = confidence_engine or ConfidenceEngine()
        self.detection_engine = detection_engine_client

    # ── public ────────────────────────────────────────────────────────────────

    async def handle(self, event: CDMEvent) -> Optional[AttackState]:
        """
        Process a single CDMEvent. Returns the resulting AttackState, or None
        if the event was a duplicate or carried no state-impacting detection.
        """
        log = logger.bind(
            event_id=str(event.event_id),
            tenant_id=event.tenant_id,
            detection_id=event.detection_id,
        )

        impact = self._resolve_state_impact(event)
        if impact is None:
            log.debug("signal.skipped.no_state_impact")
            return None

        if not await self.entity_index.mark_processed_if_new(
            event.tenant_id, str(event.event_id)
        ):
            log.info("signal.skipped.duplicate")
            return None

        try:
            entities = self._extract_entities(event)
            if not entities:
                log.warning("signal.skipped.no_entities")
                return None

            lock_key = self._lock_key_for_entities(entities)
            async with self.entity_index.lock(event.tenant_id, lock_key):
                existing_id = await self._find_attack_id(event.tenant_id, entities)
                if existing_id is not None:
                    state = await self.store.get_by_id(existing_id, event.tenant_id)
                    if state is not None and state.status == AttackStateStatus.ACTIVE:
                        return await self._update_existing(state, event, impact, entities)
                    # cache pointed at a stale/closed state — fall through to create
                return await self._create_new(event, impact, entities)
        except Exception:
            # Roll back the idempotency claim so a retry can re-process.
            await self.entity_index.unmark_processed(event.tenant_id, str(event.event_id))
            raise

    # ── helpers ───────────────────────────────────────────────────────────────

    def _resolve_state_impact(self, event: CDMEvent):
        impact = detections_registry.lookup(event.detection_id)
        if impact is not None:
            return impact
        return detections_registry.normalize_event_state_impact(event.state_impact)

    def _extract_entities(self, event: CDMEvent) -> list[tuple[str, str]]:
        entities: list[tuple[str, str]] = []
        if event.host:
            if event.host.hostname:
                entities.append(("host", event.host.hostname))
            if event.host.ip:
                entities.append(("host", event.host.ip))
        if event.user and event.user.username:
            entities.append(("user", event.user.username))
        if event.process and event.process.process_name:
            entities.append(("process", event.process.process_name))
        # Dedupe while preserving order
        seen = set()
        unique: list[tuple[str, str]] = []
        for t, v in entities:
            key = (t, v.lower())
            if key in seen:
                continue
            seen.add(key)
            unique.append((t, v))
        return unique

    def _lock_key_for_entities(self, entities: list[tuple[str, str]]) -> str:
        primary = sorted(f"{t}={v.lower()}" for t, v in entities)[0]
        return f"entity:{primary}"

    async def _find_attack_id(
        self, tenant_id: str, entities: list[tuple[str, str]]
    ) -> Optional[UUID]:
        cached = await self.entity_index.lookup_any(tenant_id, entities)
        if cached is not None:
            return cached
        for entity_type, entity_value in entities:
            states = await self.store.get_by_entity(entity_type, entity_value, tenant_id)
            if states:
                state = states[0]
                # Re-warm the cache.
                await self.entity_index.bind(tenant_id, entities, state.attack_id)
                return state.attack_id
        return None

    # ── update flow ───────────────────────────────────────────────────────────

    async def _update_existing(
        self,
        state: AttackState,
        event: CDMEvent,
        impact: detections_registry.StateImpact,
        entities: list[tuple[str, str]],
    ) -> AttackState:
        if any(e.signal_id == str(event.event_id) for e in state.evidence):
            # Defensive — Redis idempotency should have caught this.
            return state

        evidence = self._build_evidence(event, impact)

        prev_phase = state.current_phase
        prev_confidence = state.confidence
        prev_momentum = state.momentum

        state.evidence.append(evidence)
        self._merge_entities(state, event)
        self._upsert_phase_state(state, evidence, impact)

        if impact["progression"] and self.confidence.is_phase_progression(
            prev_phase, impact["transitions_to"]
        ):
            state.current_phase = impact["transitions_to"]

        confidence, momentum, impact_level = self.confidence.recalculate(state)
        state.confidence = confidence
        state.momentum = momentum
        state.impact = impact_level
        state.last_seen = max(state.last_seen, event.timestamp)
        state.last_updated = datetime.now(timezone.utc)

        await self.store.update(state)
        await self.entity_index.bind(event.tenant_id, entities, state.attack_id)

        is_escalation = self.confidence.crossed_escalation_threshold(
            prev_confidence, state.confidence
        )

        transition = AttackStateTransition(
            attack_id=state.attack_id,
            tenant_id=state.tenant_id,
            previous_phase=prev_phase,
            new_phase=state.current_phase,
            previous_confidence=prev_confidence,
            new_confidence=state.confidence,
            previous_momentum=prev_momentum,
            new_momentum=state.momentum,
            trigger_signal_id=str(event.event_id),
            trigger_detection_id=event.detection_id,
            is_escalation=is_escalation,
        )

        try:
            await self.store.record_transition(transition)
        except Exception as e:
            logger.warning("signal_handler.transition_log_failed", error=str(e))

        await self.publisher.publish_attack_updated(state, transition)
        if is_escalation:
            await self.publisher.publish_attack_escalated(state, transition)

        await self._record_signal_fire(state, evidence)

        logger.info(
            "signal.attack.updated",
            attack_id=str(state.attack_id),
            phase=state.current_phase.value,
            confidence=state.confidence,
            escalation=is_escalation,
        )
        return state

    # ── create flow ───────────────────────────────────────────────────────────

    async def _create_new(
        self,
        event: CDMEvent,
        impact: detections_registry.StateImpact,
        entities: list[tuple[str, str]],
    ) -> AttackState:
        evidence = self._build_evidence(event, impact)

        state = AttackState(
            attack_id=uuid4(),
            tenant_id=event.tenant_id,
            name=self._build_attack_name(event, impact),
            current_phase=impact["transitions_to"],
            evidence=[evidence],
            phases=[
                PhaseState(
                    phase=impact["transitions_to"],
                    status=impact["status"],
                    technique_id=evidence.technique_id,
                    technique_name=event.mitre.technique if event.mitre else None,
                    first_seen=event.timestamp,
                    last_seen=event.timestamp,
                    evidence_ids=[evidence.evidence_id],
                    confidence=impact["confidence_contribution"],
                )
            ],
            first_seen=event.timestamp,
            last_seen=event.timestamp,
        )
        self._merge_entities(state, event)

        confidence, momentum, impact_level = self.confidence.recalculate(state)
        state.confidence = confidence
        state.momentum = momentum
        state.impact = impact_level

        await self.store.create(state)
        await self.entity_index.bind(event.tenant_id, entities, state.attack_id)

        await self.publisher.publish_attack_created(state)

        await self._record_signal_fire(state, evidence)

        logger.info(
            "signal.attack.created",
            attack_id=str(state.attack_id),
            tenant_id=state.tenant_id,
            phase=state.current_phase.value,
            confidence=state.confidence,
        )
        return state

    # ── shared builders ───────────────────────────────────────────────────────

    def _build_evidence(
        self, event: CDMEvent, impact: detections_registry.StateImpact
    ) -> EvidenceItem:
        entity_type, entity_value = self._primary_entity(event)
        return EvidenceItem(
            signal_id=str(event.event_id),
            detection_id=event.detection_id,
            rule_name=event.rule_name,
            source_siem=event.source_siem,
            entity_type=entity_type,
            entity_value=entity_value,
            raw_reference=f"{event.source_siem}:{event.source_event_id}",
            timestamp=event.timestamp,
            phase=impact["transitions_to"],
            technique_id=event.mitre.technique_id if event.mitre else None,
            status_contributed=impact["status"],
            confidence_contribution=impact["confidence_contribution"],
        )

    @staticmethod
    def _primary_entity(event: CDMEvent) -> tuple[str, str]:
        if event.host and event.host.hostname:
            return ("host", event.host.hostname)
        if event.host and event.host.ip:
            return ("host", event.host.ip)
        if event.user and event.user.username:
            return ("user", event.user.username)
        if event.process and event.process.process_name:
            return ("process", event.process.process_name)
        return ("unknown", "unknown")

    @staticmethod
    def _build_attack_name(event: CDMEvent, impact: detections_registry.StateImpact) -> str:
        phase_label = impact["transitions_to"].value.replace("-", " ").title()
        target = None
        if event.host and event.host.hostname:
            target = event.host.hostname
        elif event.user and event.user.username:
            target = event.user.username
        elif event.host and event.host.ip:
            target = event.host.ip
        if target:
            return f"{phase_label}: {target}"
        return f"{phase_label}: {_PHASE_LABEL_FALLBACK}"

    @staticmethod
    def _merge_entities(state: AttackState, event: CDMEvent) -> None:
        def add(seq: list[str], value: Optional[str]) -> None:
            if value and value not in seq:
                seq.append(value)

        if event.host:
            add(state.hosts, event.host.hostname)
            add(state.hosts, event.host.ip)
        if event.user:
            add(state.users, event.user.username)
        if event.process:
            add(state.processes, event.process.process_name)

    async def _record_signal_fire(
        self,
        state: AttackState,
        evidence: EvidenceItem,
    ) -> None:
        """Best-effort post to detection-engine /internal/signals/record.

        Detection-engine is the governance layer; if it's down, correlation
        must continue. Failures are logged but never propagated.
        """
        if self.detection_engine is None or not self.detection_engine.enabled:
            return
        if not evidence.detection_id:
            return
        try:
            await self.detection_engine.record_signal(
                detection_id=evidence.detection_id,
                tenant_id=state.tenant_id,
                fired_at=evidence.timestamp,
                attack_id=state.attack_id,
                phase_contributed=evidence.phase.value,
                status_contributed=evidence.status_contributed.value,
                confidence_contribution=evidence.confidence_contribution,
            )
        except Exception as e:
            logger.warning("signal_handler.detection_record_failed", error=str(e))

    def _upsert_phase_state(
        self,
        state: AttackState,
        evidence: EvidenceItem,
        impact: detections_registry.StateImpact,
    ) -> None:
        existing = state.get_phase(impact["transitions_to"])
        if existing is None:
            state.phases.append(
                PhaseState(
                    phase=impact["transitions_to"],
                    status=impact["status"],
                    technique_id=evidence.technique_id,
                    first_seen=evidence.timestamp,
                    last_seen=evidence.timestamp,
                    evidence_ids=[evidence.evidence_id],
                    confidence=impact["confidence_contribution"],
                )
            )
            return

        existing.evidence_ids.append(evidence.evidence_id)
        existing.last_seen = max(existing.last_seen, evidence.timestamp)
        existing.confidence = min(
            existing.confidence + impact["confidence_contribution"], 1.0
        )
        # Confirmed > Observed > Blocked: only escalate, never downgrade.
        if (
            impact["status"] == PhaseStatus.CONFIRMED
            and existing.status != PhaseStatus.CONFIRMED
        ):
            existing.status = PhaseStatus.CONFIRMED
