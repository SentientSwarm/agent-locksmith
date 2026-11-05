-- Committed identities never repeat after delete/recreate, even within one second.
-- Keep the existing sealed store and all existing bytes/metadata. Existing rows
-- receive fresh identities at version zero; grants and bindings are unchanged.
CREATE TABLE oauth_sessions__new (
    incarnation INTEGER PRIMARY KEY AUTOINCREMENT,
    token_version INTEGER NOT NULL DEFAULT 0
        CHECK(typeof(token_version) = 'integer' AND token_version >= 0),
    name TEXT NOT NULL,
    session_label TEXT NOT NULL DEFAULT 'default',
    refresh_token_ciphertext BLOB NOT NULL,
    refresh_token_nonce BLOB NOT NULL,
    access_token_ciphertext BLOB,
    access_token_nonce BLOB,
    access_token_expires_at INTEGER,
    scope TEXT NOT NULL DEFAULT '',
    degraded INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    account_id TEXT,
    UNIQUE(name, session_label)
);

INSERT INTO oauth_sessions__new (
    name, session_label, refresh_token_ciphertext, refresh_token_nonce,
    access_token_ciphertext, access_token_nonce, access_token_expires_at,
    scope, degraded, created_at, updated_at, account_id
)
SELECT name, session_label, refresh_token_ciphertext, refresh_token_nonce,
    access_token_ciphertext, access_token_nonce, access_token_expires_at,
    scope, degraded, created_at, updated_at, account_id
FROM oauth_sessions;

DROP TABLE oauth_sessions;
ALTER TABLE oauth_sessions__new RENAME TO oauth_sessions;
CREATE INDEX idx_oauth_sessions_refresh_schedule
    ON oauth_sessions(degraded, access_token_expires_at);
