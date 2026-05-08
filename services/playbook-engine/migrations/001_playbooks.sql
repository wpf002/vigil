-- VIGIL Playbook Engine schema
-- One row per Temporal workflow execution. The Temporal cluster owns
-- workflow state; this table is a queryable summary so analysts can see
-- run history without going through the Temporal UI.

CREATE TABLE IF NOT EXISTS playbook_runs (
    run_id                UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    attack_id             UUID         NOT NULL,
    tenant_id             UUID         NOT NULL,
    workflow_id           TEXT         NOT NULL,
    narrative_id          TEXT,
    triggered_at          TIMESTAMPTZ  NOT NULL DEFAULT now(),
    status                TEXT         NOT NULL DEFAULT 'running',
    phase_at_trigger      TEXT         NOT NULL,
    confidence_at_trigger REAL         NOT NULL,
    completed_at          TIMESTAMPTZ,
    actions               JSONB        NOT NULL DEFAULT '[]'::jsonb,
    completed_actions     JSONB        NOT NULL DEFAULT '[]'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_playbook_runs_attack
    ON playbook_runs(attack_id, tenant_id);

CREATE INDEX IF NOT EXISTS idx_playbook_runs_status
    ON playbook_runs(status);
