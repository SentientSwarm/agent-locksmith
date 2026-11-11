-- Per-route upstream CA (#135). When set, the route trusts only these
-- certificates (PEM, validated on write); public roots and the global
-- tls.upstream_ca_bundle are not used for it. NULL keeps today's trust.
ALTER TABLE registrations ADD COLUMN upstream_ca_pem TEXT;

-- Trust is part of the destination: changing who the route trusts must not
-- inherit grants or account selections reviewed under the old trust.
CREATE TRIGGER registration_trust_changed_authority
AFTER UPDATE OF upstream_ca_pem ON registrations
WHEN OLD.upstream_ca_pem IS NOT NEW.upstream_ca_pem
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
