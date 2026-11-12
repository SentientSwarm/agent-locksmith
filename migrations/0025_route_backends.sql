-- Brokered routes phase 2: declared backends per HTTP route.
--
-- The registrations row keeps holding the ACTIVE backend's destination and
-- auth template, so admission, the proxy and the catalog are unchanged.
-- registration_backends stores declared backends; backend_bindings stashes
-- per-agent bindings for backends that are not active. active_backend NULL
-- means the implicit backend "primary".
ALTER TABLE registrations ADD COLUMN active_backend TEXT;

CREATE TABLE registration_backends (
    route           TEXT NOT NULL REFERENCES registrations(name) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    upstream        TEXT NOT NULL,
    egress          TEXT NOT NULL CHECK (egress IN ('direct', 'proxied')),
    upstream_ca_pem TEXT,
    auth_json       TEXT NOT NULL,
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL,
    PRIMARY KEY (route, name)
);

CREATE TABLE backend_bindings (
    agent_id   INTEGER NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    route      TEXT NOT NULL,
    backend    TEXT NOT NULL,
    auth_spec  TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (agent_id, route, backend),
    FOREIGN KEY (route, backend) REFERENCES registration_backends(route, name)
        ON DELETE CASCADE
);

-- A stashed binding was reviewed for its backend's destination. Moving that
-- destination invalidates it, exactly as 0009 does for active bindings.
CREATE TRIGGER backend_destination_changed_stash
AFTER UPDATE OF upstream, egress, upstream_ca_pem ON registration_backends
WHEN OLD.upstream != NEW.upstream OR OLD.egress != NEW.egress
  OR OLD.upstream_ca_pem IS NOT NEW.upstream_ca_pem
BEGIN
    DELETE FROM backend_bindings
     WHERE route = NEW.route AND backend = NEW.name;
END;

-- Written and deleted inside one switch transaction. The authority triggers
-- below skip only an update whose new destination equals the guarded target
-- exactly, with protocol and MCP configuration unchanged. Must be a real
-- table: persisted triggers cannot reference temporary tables.
CREATE TABLE route_switch_guard (
    route           TEXT PRIMARY KEY,
    upstream        TEXT NOT NULL,
    egress          TEXT NOT NULL,
    upstream_ca_pem TEXT
);

DROP TRIGGER registration_destination_changed_authority;
CREATE TRIGGER registration_destination_changed_authority
AFTER UPDATE OF upstream, egress, protocol, mcp_json ON registrations
WHEN (OLD.upstream != NEW.upstream OR OLD.egress != NEW.egress
  OR OLD.protocol != NEW.protocol OR OLD.mcp_json IS NOT NEW.mcp_json)
  AND NOT EXISTS (
    SELECT 1 FROM route_switch_guard g
     WHERE g.route = NEW.name AND g.upstream = NEW.upstream
       AND g.egress = NEW.egress AND g.upstream_ca_pem IS NEW.upstream_ca_pem
       AND NEW.protocol = OLD.protocol AND NEW.mcp_json IS OLD.mcp_json)
BEGIN
    DELETE FROM agent_credential_overrides WHERE registration = NEW.name;
    UPDATE agents SET tool_allowlist = (
        SELECT json_group_array(value) FROM json_each(agents.tool_allowlist)
        WHERE value != NEW.name
    ) WHERE grants_reviewed = 1 AND json_valid(tool_allowlist);
    UPDATE bootstrap_tokens SET scope = json_set(scope, '$.tool_allowlist', json((
        SELECT json_group_array(value) FROM json_each(bootstrap_tokens.scope, '$.tool_allowlist')
        WHERE value != NEW.name
    ))) WHERE grants_reviewed = 1 AND json_valid(scope);
END;

DROP TRIGGER registration_trust_changed_authority;
CREATE TRIGGER registration_trust_changed_authority
AFTER UPDATE OF upstream_ca_pem ON registrations
WHEN OLD.upstream_ca_pem IS NOT NEW.upstream_ca_pem
  AND NOT EXISTS (
    SELECT 1 FROM route_switch_guard g
     WHERE g.route = NEW.name AND g.upstream = NEW.upstream
       AND g.egress = NEW.egress AND g.upstream_ca_pem IS NEW.upstream_ca_pem
       AND NEW.protocol = OLD.protocol AND NEW.mcp_json IS OLD.mcp_json)
BEGIN
    DELETE FROM agent_credential_overrides WHERE registration = NEW.name;
    UPDATE agents SET tool_allowlist = (
        SELECT json_group_array(value) FROM json_each(agents.tool_allowlist)
        WHERE value != NEW.name
    ) WHERE grants_reviewed = 1 AND json_valid(tool_allowlist);
    UPDATE bootstrap_tokens SET scope = json_set(scope, '$.tool_allowlist', json((
        SELECT json_group_array(value) FROM json_each(bootstrap_tokens.scope, '$.tool_allowlist')
        WHERE value != NEW.name
    ))) WHERE grants_reviewed = 1 AND json_valid(scope);
END;
