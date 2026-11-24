-- AGENT-251: one row the daemon rewrites every few seconds to prove the
-- database still takes writes. While a write fails, /readyz reports
-- database_unwritable and proxied requests are refused with 503
-- audit_unavailable, so no request goes unaudited.
CREATE TABLE db_write_probe (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    probed_at_ms INTEGER NOT NULL
);
