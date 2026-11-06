-- Native protocol state is opt-in. Existing rows and authority remain HTTP.
ALTER TABLE registrations ADD COLUMN protocol TEXT NOT NULL DEFAULT 'http'
    CHECK(protocol = 'http' OR (protocol = 'mcp_streamable_http' AND kind = 'tool'));
ALTER TABLE registrations ADD COLUMN mcp_json TEXT;
ALTER TABLE agents ADD COLUMN mcp_epoch INTEGER NOT NULL DEFAULT 0;

CREATE TABLE registration_instances (
    name TEXT PRIMARY KEY REFERENCES registrations(name) ON DELETE CASCADE,
    instance_id TEXT NOT NULL UNIQUE DEFAULT (lower(hex(randomblob(16)))),
    revision INTEGER NOT NULL DEFAULT 1
);
INSERT INTO registration_instances(name) SELECT name FROM registrations;
CREATE TRIGGER registration_instance_created AFTER INSERT ON registrations BEGIN
    INSERT INTO registration_instances(name) VALUES (NEW.name);
END;
CREATE TRIGGER registration_instance_updated AFTER UPDATE ON registrations BEGIN
    UPDATE registration_instances SET revision = revision + 1 WHERE name = NEW.name;
END;

-- Protocol/config changes cannot reinterpret earlier HTTP grants or selections.
DROP TRIGGER registration_destination_changed_authority;
CREATE TRIGGER registration_destination_changed_authority
AFTER UPDATE OF upstream, egress, protocol, mcp_json ON registrations
WHEN OLD.upstream != NEW.upstream OR OLD.egress != NEW.egress
  OR OLD.protocol != NEW.protocol OR OLD.mcp_json IS NOT NEW.mcp_json
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

-- Policy/binding epochs defeat immediate ABA without touching HTTP semantics.
-- last_used_at authentication touches and OAuth token rotations are excluded.
CREATE TRIGGER native_agent_policy AFTER UPDATE OF tool_allowlist, tool_denylist,
    grants_reviewed, revoked_at, expires_at, cert_identity ON agents
WHEN OLD.tool_allowlist IS NOT NEW.tool_allowlist
  OR OLD.tool_denylist IS NOT NEW.tool_denylist
  OR OLD.grants_reviewed != NEW.grants_reviewed
  OR OLD.revoked_at IS NOT NEW.revoked_at OR OLD.expires_at IS NOT NEW.expires_at
  OR OLD.cert_identity IS NOT NEW.cert_identity
BEGIN
    UPDATE agents SET mcp_epoch = mcp_epoch + 1 WHERE id = NEW.id;
END;
CREATE TRIGGER native_binding_created AFTER INSERT ON agent_credential_overrides BEGIN
    UPDATE agents SET mcp_epoch = mcp_epoch + 1 WHERE id = NEW.agent_id;
END;
CREATE TRIGGER native_binding_updated AFTER UPDATE ON agent_credential_overrides BEGIN
    UPDATE agents SET mcp_epoch = mcp_epoch + 1 WHERE id = NEW.agent_id;
END;
CREATE TRIGGER native_binding_deleted AFTER DELETE ON agent_credential_overrides BEGIN
    UPDATE agents SET mcp_epoch = mcp_epoch + 1 WHERE id = OLD.agent_id;
END;
