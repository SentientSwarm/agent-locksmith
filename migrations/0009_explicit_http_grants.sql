-- D4: old policies require explicit review before HTTP use. No automatic grants.
ALTER TABLE agents ADD COLUMN grants_reviewed INTEGER NOT NULL DEFAULT 0;
ALTER TABLE bootstrap_tokens ADD COLUMN grants_reviewed INTEGER NOT NULL DEFAULT 0;

-- Lifecycle authority invalidation is part of the same SQLite write, including
-- seed/repository writes. Disable/re-enable keeps identity; replacement does not.
CREATE TRIGGER registration_deleted_authority AFTER DELETE ON registrations

BEGIN
    DELETE FROM agent_credential_overrides WHERE registration = OLD.name;
    UPDATE agents SET tool_allowlist = (
        SELECT json_group_array(value) FROM json_each(agents.tool_allowlist)
        WHERE value != OLD.name
    ) WHERE grants_reviewed = 1 AND json_valid(tool_allowlist);
    UPDATE bootstrap_tokens SET scope = json_set(scope, '$.tool_allowlist', json((
        SELECT json_group_array(value) FROM json_each(bootstrap_tokens.scope, '$.tool_allowlist')
        WHERE value != OLD.name
    ))) WHERE grants_reviewed = 1 AND json_valid(scope);
END;

CREATE TRIGGER registration_created_authority AFTER INSERT ON registrations

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

CREATE TRIGGER registration_destination_changed_authority AFTER UPDATE OF upstream, egress ON registrations
WHEN OLD.upstream != NEW.upstream OR OLD.egress != NEW.egress
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
