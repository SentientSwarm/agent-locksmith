-- M2 initial schema. SPEC §4.6.2.
-- Forward-only per INF-11; rollback is operator backup-restore.
--
-- WAL-mode PRAGMAs are applied per-connection by the MigrationRunner
-- (src/migrations.rs / T2.3) using SqliteConnectOptions and the
-- after_connect hook. They are NOT inlined here because sqlx wraps each
-- migration in a transaction, and PRAGMAs like `synchronous` cannot be
-- changed inside a transaction.

CREATE TABLE agents (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    public_id       TEXT NOT NULL UNIQUE,
    name            TEXT NOT NULL UNIQUE,
    description     TEXT,
    secret_hash     TEXT NOT NULL,
    tool_allowlist  TEXT,
    tool_denylist   TEXT,
    metadata        TEXT,
    cert_identity   TEXT,
    registered_at   INTEGER NOT NULL,
    last_used_at    INTEGER,
    expires_at      INTEGER,
    revoked_at      INTEGER,
    role_id         INTEGER
);

CREATE INDEX idx_agents_active ON agents(public_id) WHERE revoked_at IS NULL;
CREATE INDEX idx_agents_cert_identity ON agents(cert_identity)
    WHERE cert_identity IS NOT NULL AND revoked_at IS NULL;

CREATE TABLE bootstrap_tokens (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    public_id          TEXT NOT NULL UNIQUE,
    secret_hash        TEXT NOT NULL,
    scope              TEXT NOT NULL,
    created_by         TEXT NOT NULL,
    created_at         INTEGER NOT NULL,
    expires_at         INTEGER,
    used_at            INTEGER,
    used_by_agent_id   INTEGER REFERENCES agents(id),
    revoked_at         INTEGER
);

CREATE INDEX idx_bootstrap_active ON bootstrap_tokens(public_id)
    WHERE used_at IS NULL AND revoked_at IS NULL;

CREATE TABLE audit (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    ts                 INTEGER NOT NULL,
    schema_version     INTEGER NOT NULL DEFAULT 1,
    event_class        TEXT NOT NULL CHECK (event_class IN ('proxy', 'operator', 'security')),
    event              TEXT NOT NULL,
    agent_public_id    TEXT,
    operator_name      TEXT,
    tool               TEXT,
    upstream_host      TEXT,
    method             TEXT,
    path               TEXT,
    status             INTEGER,
    latency_ms         INTEGER,
    decision           TEXT NOT NULL CHECK (decision IN ('allowed', 'denied', 'error')),
    auth_method        TEXT,
    origin_ip          TEXT,
    details            TEXT
);

CREATE INDEX idx_audit_ts ON audit(ts);
CREATE INDEX idx_audit_agent_ts ON audit(agent_public_id, ts) WHERE agent_public_id IS NOT NULL;
CREATE INDEX idx_audit_class_ts ON audit(event_class, ts);
CREATE INDEX idx_audit_tool_ts ON audit(tool, ts) WHERE tool IS NOT NULL;
