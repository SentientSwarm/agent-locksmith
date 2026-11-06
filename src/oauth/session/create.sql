INSERT INTO oauth_sessions (
    name, session_label, refresh_token_ciphertext, refresh_token_nonce,
    access_token_ciphertext, access_token_nonce, access_token_expires_at,
    scope, degraded, created_at, updated_at, account_id
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?)
RETURNING *
