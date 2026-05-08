-- VIGIL Detection Engine schema
-- Tracks detection versioning, per-signal contributions, and rolled-up
-- performance windows. The compiled YAML manifest is the source of truth
-- for detection content; this schema layers governance on top.

CREATE TABLE IF NOT EXISTS detection_versions (
    version_id       UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    detection_id     TEXT         NOT NULL,
    version          TEXT         NOT NULL,
    yaml_content     TEXT         NOT NULL,
    compiled_spl     TEXT,
    compiled_kql     TEXT,
    compiled_eql     TEXT,
    att_ck_tactic    TEXT         NOT NULL,
    att_ck_technique TEXT         NOT NULL,
    state_impact     JSONB        NOT NULL,
    status           TEXT         NOT NULL DEFAULT 'active',
    deployed_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    deployed_by      UUID,
    tenant_id        UUID         NOT NULL,
    notes            TEXT
);

CREATE TABLE IF NOT EXISTS detection_signals (
    signal_id               UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    detection_id            TEXT         NOT NULL,
    tenant_id               UUID         NOT NULL,
    fired_at                TIMESTAMPTZ  NOT NULL,
    attack_id               UUID,
    phase_contributed       TEXT,
    status_contributed      TEXT,
    confidence_contribution REAL,
    was_false_positive      BOOLEAN      NOT NULL DEFAULT FALSE,
    closed_as               TEXT
);

CREATE TABLE IF NOT EXISTS detection_performance (
    perf_id          UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    detection_id     TEXT         NOT NULL,
    tenant_id        UUID         NOT NULL,
    period_start     TIMESTAMPTZ  NOT NULL,
    period_end       TIMESTAMPTZ  NOT NULL,
    total_fires      INT          NOT NULL DEFAULT 0,
    false_positives  INT          NOT NULL DEFAULT 0,
    true_positives   INT          NOT NULL DEFAULT 0,
    escalations      INT          NOT NULL DEFAULT 0,
    fp_rate          REAL,
    avg_confidence   REAL,
    computed_at      TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_detection_signals_detection
    ON detection_signals(detection_id, tenant_id);

CREATE INDEX IF NOT EXISTS idx_detection_signals_fired
    ON detection_signals(fired_at);

CREATE INDEX IF NOT EXISTS idx_detection_versions_detection
    ON detection_versions(detection_id, tenant_id);

CREATE INDEX IF NOT EXISTS idx_detection_performance_detection
    ON detection_performance(detection_id, tenant_id);
