-- VIGIL public API keys + webhooks.
--
-- api_keys  Public-API authentication. Keys are issued in plaintext exactly
--           once at creation and stored as bcrypt hashes thereafter. The
--           short prefix is non-secret and shown in the UI for identification.
--
-- webhooks  Customer endpoints to receive event deliveries. The HMAC secret
--           is required for the customer to verify signatures.

CREATE TABLE IF NOT EXISTS api_keys (
    key_id        UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID         NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    created_by    UUID         NOT NULL REFERENCES users(user_id),
    name          TEXT         NOT NULL,
    key_prefix    TEXT         NOT NULL,
    key_hash      TEXT         NOT NULL,
    scopes        TEXT[]       NOT NULL DEFAULT '{}',
    last_used_at  TIMESTAMPTZ,
    expires_at    TIMESTAMPTZ,
    revoked       BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_api_keys_tenant ON api_keys(tenant_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_prefix ON api_keys(key_prefix);

CREATE TABLE IF NOT EXISTS webhooks (
    webhook_id     UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id      UUID         NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    url            TEXT         NOT NULL,
    secret         TEXT         NOT NULL,
    events         TEXT[]       NOT NULL,
    active         BOOLEAN      NOT NULL DEFAULT TRUE,
    last_fired_at  TIMESTAMPTZ,
    failure_count  INT          NOT NULL DEFAULT 0,
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_webhooks_tenant ON webhooks(tenant_id);
