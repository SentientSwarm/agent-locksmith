DELETE FROM oauth_sessions
WHERE kind = 'legacy' AND incarnation = ? AND name = ? AND session_label = ? AND token_version = ?
    AND refresh_pending = 0
