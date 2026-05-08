-- Track per-key request count so the Settings page can show a meaningful
-- usage signal alongside last_used_at. Incremented on every successful
-- bearer-token auth via KeyStore.touch_last_used().

ALTER TABLE api_keys
    ADD COLUMN IF NOT EXISTS use_count BIGINT NOT NULL DEFAULT 0;
