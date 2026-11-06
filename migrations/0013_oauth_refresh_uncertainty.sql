-- A committed pending attempt is unavailable after restart, even if the old
-- access token has not expired. Never reset this marker during startup.
ALTER TABLE oauth_sessions ADD COLUMN refresh_pending INTEGER NOT NULL DEFAULT 0
    CHECK(refresh_pending IN (0, 1));
