-- VIGIL AttackState persistence schema
-- AttackState is stored as a single JSONB column (full Pydantic serialization).
-- Indexed columns mirror frequently-filtered fields from the JSONB body.

CREATE TABLE IF NOT EXISTS attack_states (
    attack_id        UUID         PRIMARY KEY,
    tenant_id        TEXT         NOT NULL,
    name             TEXT         NOT NULL,
    status           TEXT         NOT NULL,
    current_phase    TEXT         NOT NULL,
    confidence       REAL         NOT NULL,
    momentum         TEXT         NOT NULL,
    impact           TEXT         NOT NULL,
    state            JSONB        NOT NULL,
    first_seen       TIMESTAMPTZ  NOT NULL,
    last_seen        TIMESTAMPTZ  NOT NULL,
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_attack_states_tenant_status
    ON attack_states (tenant_id, status);

CREATE INDEX IF NOT EXISTS ix_attack_states_tenant_phase_confidence
    ON attack_states (tenant_id, current_phase, confidence DESC);

CREATE INDEX IF NOT EXISTS ix_attack_states_tenant_last_seen
    ON attack_states (tenant_id, last_seen DESC);

CREATE INDEX IF NOT EXISTS ix_attack_states_users_gin
    ON attack_states USING GIN ((state -> 'users'));

CREATE INDEX IF NOT EXISTS ix_attack_states_hosts_gin
    ON attack_states USING GIN ((state -> 'hosts'));

CREATE INDEX IF NOT EXISTS ix_attack_states_processes_gin
    ON attack_states USING GIN ((state -> 'processes'));

-- Append-only transition log. Useful for audit and replay.
CREATE TABLE IF NOT EXISTS attack_state_transitions (
    transition_id        UUID         PRIMARY KEY,
    attack_id            UUID         NOT NULL REFERENCES attack_states(attack_id) ON DELETE CASCADE,
    tenant_id            TEXT         NOT NULL,
    previous_phase       TEXT,
    new_phase            TEXT         NOT NULL,
    previous_confidence  REAL         NOT NULL,
    new_confidence       REAL         NOT NULL,
    previous_momentum    TEXT         NOT NULL,
    new_momentum         TEXT         NOT NULL,
    trigger_signal_id    TEXT         NOT NULL,
    trigger_detection_id TEXT,
    is_escalation        BOOLEAN      NOT NULL DEFAULT FALSE,
    transition_at        TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_attack_state_transitions_attack
    ON attack_state_transitions (attack_id, transition_at DESC);
