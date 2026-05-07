-- VIGIL auth schema. Tenants, users, refresh tokens.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS tenants (
    tenant_id     UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    name          TEXT         NOT NULL,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS users (
    user_id       UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID         NOT NULL REFERENCES tenants(tenant_id),
    email         TEXT         UNIQUE NOT NULL,
    password_hash TEXT         NOT NULL,
    role          TEXT         NOT NULL DEFAULT 'analyst',
    is_active     BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    last_login    TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    token_id      UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       UUID         NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    token_hash    TEXT         NOT NULL,
    expires_at    TIMESTAMPTZ  NOT NULL,
    revoked       BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_tenant ON users(tenant_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON refresh_tokens(user_id);
