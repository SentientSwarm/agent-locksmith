-- Phase J / M2 · T2.5 (LOG-1, WEM-446): operational-log stream.
--
-- Structured operational event stream — DISTINCT from the `audit` table.
-- Audit records agent/operator decisions (who did what to whom); this
-- table records daemon-internal operational events (config reloads,
-- OAuth refresh degradations, registration mutations, credential-store
-- degradations). Operators query it via GET /admin/operator/logs.
--
-- Secret-free by contract (LOG-4): rows carry event names + non-secret
-- context only. No credential VALUE ever lands here — the emitter and
-- the query route are the only writers/readers, and neither surfaces a
-- secret. The retention sweeper (T2.8) hard-deletes rows older than the
-- configured window on its own interval, independent of audit retention.

CREATE TABLE IF NOT EXISTS operational_logs (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_ms     INTEGER NOT NULL,
    level     TEXT    NOT NULL,
    component TEXT    NOT NULL,
    event     TEXT    NOT NULL,
    message   TEXT    NOT NULL,
    fields    TEXT
);

-- Time-window queries + the retention sweep (DELETE WHERE ts_ms < cutoff).
CREATE INDEX IF NOT EXISTS idx_operational_logs_ts
    ON operational_logs (ts_ms);

-- Component + level filtering for operator queries.
CREATE INDEX IF NOT EXISTS idx_operational_logs_component_level
    ON operational_logs (component, level);
