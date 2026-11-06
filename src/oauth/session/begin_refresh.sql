UPDATE oauth_sessions SET refresh_pending = 1, updated_at = ?,
    token_version = token_version + 1
WHERE kind = 'legacy' AND incarnation = ? AND name = ? AND session_label = ? AND token_version = ?
    AND refresh_pending = 0 AND degraded = 0
    AND token_version < 9223372036854775806
RETURNING *
