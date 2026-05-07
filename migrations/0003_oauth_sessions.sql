-- Phase F (v2.0.0): OAuth session token cache.
--
-- Stores AES-GCM-sealed refresh + access tokens for AuthSpec::OauthPkce
-- and AuthSpec::OauthDeviceCode registrations. See ADR-0005 D2.
--
-- Sealing key sourced from `LOCKSMITH_OAUTH_SEALING_KEY` env var at
-- daemon startup (32-byte random, base64-encoded). Per-row 12-byte
-- AES-GCM nonce. Tampering with ciphertext fails the GCM tag check at
-- decrypt time and returns a "ciphertext invalid" error.
--
-- Lifecycle:
--   * INSERT — first-time auth bootstrap (Phase F.4 CLI). Operator
--     completes the OAuth flow; daemon receives refresh token,
--     exchanges for access token, seals both, INSERTs row.
--   * UPDATE — background refresh (Phase F.3) replaces
--     access_token_ciphertext + access_token_nonce + access_token_expires_at.
--     refresh_token_* updated only if provider rotates the refresh
--     token.
--   * UPDATE degraded=1 — refresh failed (revoked / 5xx / network).
--     Subsequent proxy calls 503 with `oauth_refresh_failed`. Operator
--     re-bootstraps (which UPSERTs and clears degraded).
--   * DELETE — operator runs `locksmith oauth revoke <name>`. Cache
--     cleared; admin GET /tools|/models still shows the registration
--     but proxy calls 503 until next bootstrap.
--
-- One row per registration name (PK matches registrations.name).
-- Cross-registration token sharing is not supported; multi-account
-- workflows use distinct registration names (e.g., codex-personal vs
-- codex-team).

CREATE TABLE oauth_sessions (
    -- Foreign-key shape mirrors registrations.name. SQLite doesn't
    -- enforce FK by default (PRAGMA foreign_keys=ON in pool config);
    -- repo logic enforces the (name, kind=*) lookup explicitly.
    name                       TEXT NOT NULL PRIMARY KEY,

    -- AES-GCM ciphertext + nonce for the refresh token. Refresh tokens
    -- are long-lived (provider-defined, often 30+ days) and survive
    -- daemon restarts. Sealing key from LOCKSMITH_OAUTH_SEALING_KEY.
    refresh_token_ciphertext   BLOB NOT NULL,
    refresh_token_nonce        BLOB NOT NULL,

    -- AES-GCM ciphertext + nonce for the current access token. NULL
    -- only between INSERT (no first refresh yet) and the daemon's
    -- subsequent token exchange — in practice the bootstrap CLI
    -- triggers an immediate refresh so this is populated by the time
    -- the row is committed.
    access_token_ciphertext    BLOB,
    access_token_nonce         BLOB,

    -- Unix seconds of access-token expiry. The background refresh task
    -- (Phase F.3) schedules refreshes at
    -- `expires_at - max(60s, min(300s, lifetime / 4))` per ADR-0005 D3.
    access_token_expires_at    INTEGER,

    -- Space-delimited OAuth scopes granted by the provider, captured
    -- from the bootstrap response. Used for display / status output;
    -- not consulted on the proxy hot path.
    scope                      TEXT NOT NULL DEFAULT '',

    -- 0 = healthy, 1 = degraded (refresh failed; operator action
    -- required). Per ADR-0005 D6, the proxy returns 503 with
    -- `oauth_refresh_failed` envelope code while degraded=1.
    degraded                   INTEGER NOT NULL DEFAULT 0,

    -- Unix seconds. created_at is set at first bootstrap; never
    -- updated. updated_at bumps on every refresh / re-bootstrap.
    -- Together they yield a stable session identity (used by the
    -- audit oauth_session_id field — sha256(name||':'||created_at),
    -- truncated 16 hex).
    created_at                 INTEGER NOT NULL,
    updated_at                 INTEGER NOT NULL
);

-- Background refresh task scans by `degraded=0 ORDER BY
-- access_token_expires_at ASC` to find the next session needing
-- refresh. Index supports that scan path.
CREATE INDEX idx_oauth_sessions_refresh_schedule
    ON oauth_sessions(degraded, access_token_expires_at);
