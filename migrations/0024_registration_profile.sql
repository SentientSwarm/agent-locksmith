-- Brokered routes phase 1: a route's request profile. NULL means infer from
-- the upstream (the pre-0024 rule), so existing routes keep their behaviour.
-- A profile is behaviour, not destination: no authority trigger.
ALTER TABLE registrations ADD COLUMN profile TEXT
    CHECK (profile IS NULL OR profile IN ('generic', 'openai-codex-responses'));
