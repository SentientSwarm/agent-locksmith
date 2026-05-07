-- Phase G (v2.0.0): OAuth session labels.
--
-- Extends the v0.2.0 / Phase F oauth_sessions table to hold N sessions
-- per registration name, keyed by (name, session_label). Default
-- behavior — a single session per registration — is preserved by
-- setting session_label='default' on existing rows and on writes that
-- omit the label.
--
-- Why labels: with shared OAuth (one ChatGPT account, one refresh
-- token), an operator can leave session_label='default' forever. With
-- per-agent OAuth (separate ChatGPT accounts per agent, distinct
-- quotas), the operator bootstraps multiple sessions under the same
-- registration: (codex, "hermes"), (codex, "openclaw"). Per-agent
-- credential overrides (migration 0005) point each agent at its
-- session via the override's auth_spec.session_label.
--
-- See agents-stack/docs/spec/v0.2.0.md "Per-agent credential overrides
-- + OAuth session labels (Phase G)" for the full design.
--
-- SQLite can't ALTER a primary key. Standard rebuild pattern:
--   1. Create new table with the desired shape.
--   2. Copy rows, defaulting session_label to 'default'.
--   3. Drop the old table.
--   4. Rename the new one into place.
--   5. Recreate the index.

CREATE TABLE oauth_sessions__new (
    name                       TEXT NOT NULL,
    -- Session label. Defaults to 'default' for the shared-credential
    -- case. Operators using per-agent OAuth set distinct labels per
    -- session under the same registration name.
    session_label              TEXT NOT NULL DEFAULT 'default',

    refresh_token_ciphertext   BLOB NOT NULL,
    refresh_token_nonce        BLOB NOT NULL,
    access_token_ciphertext    BLOB,
    access_token_nonce         BLOB,
    access_token_expires_at    INTEGER,
    scope                      TEXT NOT NULL DEFAULT '',
    degraded                   INTEGER NOT NULL DEFAULT 0,
    created_at                 INTEGER NOT NULL,
    updated_at                 INTEGER NOT NULL,

    PRIMARY KEY (name, session_label)
);

INSERT INTO oauth_sessions__new (
    name, session_label,
    refresh_token_ciphertext, refresh_token_nonce,
    access_token_ciphertext, access_token_nonce,
    access_token_expires_at, scope, degraded,
    created_at, updated_at
)
SELECT
    name, 'default',
    refresh_token_ciphertext, refresh_token_nonce,
    access_token_ciphertext, access_token_nonce,
    access_token_expires_at, scope, degraded,
    created_at, updated_at
FROM oauth_sessions;

DROP TABLE oauth_sessions;
ALTER TABLE oauth_sessions__new RENAME TO oauth_sessions;

-- Refresh task scan path: same shape as v0.2.0, scans for sessions
-- nearing expiry across all (name, label) tuples.
CREATE INDEX idx_oauth_sessions_refresh_schedule
    ON oauth_sessions(degraded, access_token_expires_at);
