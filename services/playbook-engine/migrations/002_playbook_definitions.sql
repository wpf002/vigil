-- VIGIL Playbook Engine — authored playbook definitions.
-- Tenant-scoped, editable playbooks (the build-a-playbook feature). The
-- consumer/dispatcher merge enabled definitions with the static YAML library
-- when selecting a playbook for an attack.

CREATE TABLE IF NOT EXISTS playbook_definitions (
    definition_id         UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id             UUID         NOT NULL,
    name                  TEXT         NOT NULL,
    enabled               BOOLEAN      NOT NULL DEFAULT TRUE,
    -- structured trigger (mirrors narrative_loader.Playbook)
    trigger_mode          TEXT         NOT NULL DEFAULT 'auto',
    trigger_phase         TEXT,
    trigger_status        TEXT,
    min_confidence        REAL         NOT NULL DEFAULT 0,
    trigger_detection_id  TEXT,
    -- list of {action_type, target, kind, priority, automated, description}
    actions               JSONB        NOT NULL DEFAULT '[]'::jsonb,
    created_by            UUID,
    created_at            TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_playbook_definitions_tenant
    ON playbook_definitions(tenant_id, enabled);
