-- AGENT-266: per-agent, per-route rate limits. A NULL agent_id is the
-- route default; an agent row overrides it for that agent. SQLite treats
-- NULLs as distinct in a primary key, so uniqueness is a unique index on
-- the agent id with NULL folded to 0 (no agent has id 0).
CREATE TABLE rate_limits (
    route TEXT NOT NULL,
    agent_id INTEGER NULL REFERENCES agents(id) ON DELETE CASCADE,
    requests_per_minute INTEGER NOT NULL CHECK (requests_per_minute > 0),
    max_concurrent INTEGER NULL CHECK (max_concurrent > 0),
    updated_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX rate_limits_route_agent
    ON rate_limits (route, COALESCE(agent_id, 0));
