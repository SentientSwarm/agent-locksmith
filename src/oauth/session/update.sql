UPDATE oauth_sessions SET
    access_token_ciphertext = ?, access_token_nonce = ?, access_token_expires_at = ?,
    refresh_token_ciphertext = COALESCE(?, refresh_token_ciphertext),
    refresh_token_nonce = COALESCE(?, refresh_token_nonce),
    account_id = ?, degraded = 0, refresh_pending = 0, updated_at = ?, token_version = token_version + 1
WHERE incarnation = ? AND name = ? AND session_label = ? AND token_version = ?
    AND token_version < 9223372036854775807
    AND refresh_pending = ?
RETURNING *
