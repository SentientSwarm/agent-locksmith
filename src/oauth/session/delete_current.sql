DELETE FROM oauth_sessions
WHERE incarnation = ? AND name = ? AND session_label = ? AND token_version = ?
