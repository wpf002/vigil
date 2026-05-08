-- VIGIL detection marketplace.
--
-- marketplace_listings  Detections published from one tenant to be importable
--                       by others. is_curated marks VIGIL-staff publications
--                       (the platform tenant publishes D1–D4 here).
-- marketplace_imports   Audit trail of which tenant imported what; used to
--                       count downloads and prevent duplicate imports.

CREATE TABLE IF NOT EXISTS marketplace_listings (
    listing_id          UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    detection_id        TEXT         NOT NULL,
    publisher_tenant_id UUID         NOT NULL,
    name                TEXT         NOT NULL,
    description         TEXT,
    att_ck_tactic       TEXT         NOT NULL,
    att_ck_technique    TEXT         NOT NULL,
    yaml_content        TEXT         NOT NULL,
    version             TEXT         NOT NULL,
    is_curated          BOOLEAN      DEFAULT FALSE,
    downloads           INT          DEFAULT 0,
    published_at        TIMESTAMPTZ  DEFAULT now(),
    updated_at          TIMESTAMPTZ  DEFAULT now(),
    status              TEXT         DEFAULT 'active'
);

CREATE TABLE IF NOT EXISTS marketplace_imports (
    import_id           UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    listing_id          UUID         REFERENCES marketplace_listings(listing_id),
    importing_tenant_id UUID         NOT NULL,
    imported_at         TIMESTAMPTZ  DEFAULT now(),
    local_detection_id  TEXT,
    active              BOOLEAN      DEFAULT TRUE
);

CREATE INDEX IF NOT EXISTS idx_marketplace_tactic    ON marketplace_listings(att_ck_tactic);
CREATE INDEX IF NOT EXISTS idx_marketplace_publisher ON marketplace_listings(publisher_tenant_id);
CREATE INDEX IF NOT EXISTS idx_imports_tenant       ON marketplace_imports(importing_tenant_id);
