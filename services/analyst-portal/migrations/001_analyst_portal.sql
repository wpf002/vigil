-- VIGIL Analyst Portal schema
-- Tables here are owned by the VIGIL managed-service tier (analysts who
-- work customer environments on behalf of VIGIL). Distinct from end-user
-- tables in the api service.

CREATE TABLE IF NOT EXISTS analyst_shifts (
    shift_id                  UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    analyst_id                UUID         NOT NULL,
    start_time                TIMESTAMPTZ  NOT NULL,
    end_time                  TIMESTAMPTZ,
    status                    TEXT         NOT NULL DEFAULT 'active',
    attacks_handled           INT          NOT NULL DEFAULT 0,
    escalations_received      INT          NOT NULL DEFAULT 0,
    mean_response_time_seconds INT
);

CREATE TABLE IF NOT EXISTS sla_configs (
    sla_id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID         NOT NULL,
    tier                TEXT         NOT NULL,
    response_minutes    INT          NOT NULL,
    escalation_minutes  INT          NOT NULL,
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT now(),
    UNIQUE(tenant_id, tier)
);

CREATE TABLE IF NOT EXISTS analyst_actions (
    action_id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    attack_id              UUID         NOT NULL,
    tenant_id              UUID         NOT NULL,
    analyst_id             UUID         NOT NULL,
    action_type            TEXT         NOT NULL,
    action_detail          JSONB,
    response_time_seconds  INT,
    sla_met                BOOLEAN,
    created_at             TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS escalation_queue (
    queue_id          UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    attack_id         UUID         NOT NULL,
    tenant_id         UUID         NOT NULL,
    escalated_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    priority          TEXT         NOT NULL,
    assigned_to       UUID,
    acknowledged_at   TIMESTAMPTZ,
    resolved_at       TIMESTAMPTZ,
    sla_deadline      TIMESTAMPTZ  NOT NULL,
    sla_breached      BOOLEAN      NOT NULL DEFAULT FALSE,
    notes             TEXT
);

CREATE INDEX IF NOT EXISTS idx_escalation_queue_unassigned
    ON escalation_queue(assigned_to) WHERE assigned_to IS NULL;

CREATE INDEX IF NOT EXISTS idx_escalation_queue_tenant
    ON escalation_queue(tenant_id, escalated_at);

CREATE INDEX IF NOT EXISTS idx_analyst_actions_attack
    ON analyst_actions(attack_id, tenant_id);

CREATE INDEX IF NOT EXISTS idx_analyst_shifts_analyst
    ON analyst_shifts(analyst_id, status);
