-- VIGIL audit log.
--
-- Append-only by design — there is no DELETE endpoint, and rows are
-- never updated. Auditors require an immutable log; we enforce this at
-- the application layer (no DELETE route exposed) and surface it via
-- the reporting service for SOC 2 / PCI evidence.
--
-- DO NOT add an UPDATE or DELETE handler against this table. Retention
-- is unlimited by design; if a future requirement needs trimming, do it
-- via a dedicated archival job that exports to immutable cold storage
-- before deleting.

CREATE TABLE IF NOT EXISTS audit_log (
    log_id        UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID,
    user_id       UUID,
    event_type    TEXT         NOT NULL,
    resource_type TEXT,
    resource_id   TEXT,
    ip_address    TEXT,
    user_agent    TEXT,
    detail        JSONB,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_audit_log_tenant ON audit_log(tenant_id, created_at);
CREATE INDEX IF NOT EXISTS idx_audit_log_user ON audit_log(user_id, created_at);
CREATE INDEX IF NOT EXISTS idx_audit_log_event_type ON audit_log(event_type, created_at);
