-- VIGIL reporting service.
--
-- metric_snapshots holds rolled-up tenant metrics computed on a schedule
-- (daily at 00:05 UTC). The reporting service uses these snapshots to
-- back the executive dashboard and the compliance evidence packs.
--
-- This table is append-only; the scheduler inserts a new row per
-- (tenant, snapshot_type, period_start) tuple.

CREATE TABLE IF NOT EXISTS metric_snapshots (
    snapshot_id    UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id      UUID         NOT NULL,
    snapshot_type  TEXT         NOT NULL,
    period_start   TIMESTAMPTZ  NOT NULL,
    period_end     TIMESTAMPTZ  NOT NULL,
    metrics        JSONB        NOT NULL,
    computed_at    TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_snapshots_tenant_type
    ON metric_snapshots(tenant_id, snapshot_type, period_start);
