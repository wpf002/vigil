-- Adds onboarding_complete flag to users.
-- Used by the frontend to decide whether to redirect a freshly-registered
-- user into the onboarding wizard.

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS onboarding_complete BOOLEAN NOT NULL DEFAULT FALSE;
