UPDATE oauth_sessions SET degraded = 1, updated_at = ?, token_version = token_version + 1
WHERE incarnation = ? AND name = ? AND session_label = ? AND token_version = ?
    AND token_version < 9223372036854775807
    AND refresh_pending = 0
