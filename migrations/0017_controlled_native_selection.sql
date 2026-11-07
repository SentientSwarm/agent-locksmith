-- Delegation is a new, owner-stamped selection, never a registration template.
-- No account rebuild: sealed bytes, nullable fields and sequence highwater stay intact.
CREATE TRIGGER controlled_selection_not_registration_insert BEFORE INSERT ON registrations
WHEN CASE WHEN json_valid(NEW.auth_json) THEN json_extract(NEW.auth_json,'$.kind')='controlled_oauth' ELSE 0 END BEGIN
    SELECT RAISE(ABORT,'selection_only');
END;
CREATE TRIGGER controlled_selection_not_registration_update BEFORE UPDATE OF auth_json ON registrations
WHEN CASE WHEN json_valid(NEW.auth_json) THEN json_extract(NEW.auth_json,'$.kind')='controlled_oauth' ELSE 0 END BEGIN
    SELECT RAISE(ABORT,'selection_only');
END;
CREATE TRIGGER controlled_selection_insert BEFORE INSERT ON agent_credential_overrides
WHEN CASE WHEN json_valid(NEW.auth_spec) THEN json_extract(NEW.auth_spec,'$.kind')='controlled_oauth' ELSE 0 END BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM oauth_sessions o JOIN registrations r ON r.name=o.name
        WHERE o.name=NEW.registration AND o.kind='controlled_linear_v1'
        AND o.session_label=json_extract(NEW.auth_spec,'$.session_label')
        AND o.owner_id=json_extract(NEW.auth_spec,'$.owner_id')
        AND o.incarnation=json_extract(NEW.auth_spec,'$.incarnation')
        AND json_type(NEW.auth_spec,'$.incarnation')='integer'
        AND o.profile_id=json_extract(NEW.auth_spec,'$.profile_id')
        AND o.profile_digest=json_extract(NEW.auth_spec,'$.profile_digest')
        AND r.kind='tool' AND r.protocol='mcp_streamable_http'
        AND r.disabled=0 AND r.seed=0 AND r.egress='direct'
        AND json_extract(r.mcp_json,'$.definition') IS NULL
    ) THEN RAISE(ABORT,'controlled_selection_invalid') END;
END;
CREATE TRIGGER controlled_selection_update BEFORE UPDATE OF auth_spec,registration ON agent_credential_overrides
WHEN CASE WHEN json_valid(NEW.auth_spec) THEN json_extract(NEW.auth_spec,'$.kind')='controlled_oauth' ELSE 0 END BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM oauth_sessions o JOIN registrations r ON r.name=o.name
        WHERE o.name=NEW.registration AND o.kind='controlled_linear_v1'
        AND o.session_label=json_extract(NEW.auth_spec,'$.session_label')
        AND o.owner_id=json_extract(NEW.auth_spec,'$.owner_id')
        AND o.incarnation=json_extract(NEW.auth_spec,'$.incarnation')
        AND json_type(NEW.auth_spec,'$.incarnation')='integer'
        AND o.profile_id=json_extract(NEW.auth_spec,'$.profile_id')
        AND o.profile_digest=json_extract(NEW.auth_spec,'$.profile_digest')
        AND r.kind='tool' AND r.protocol='mcp_streamable_http'
        AND r.disabled=0 AND r.seed=0 AND r.egress='direct'
        AND json_extract(r.mcp_json,'$.definition') IS NULL
    ) THEN RAISE(ABORT,'controlled_selection_invalid') END;
END;
CREATE TRIGGER controlled_account_deleted AFTER DELETE ON oauth_sessions
WHEN OLD.kind='controlled_linear_v1' BEGIN
    DELETE FROM agent_credential_overrides WHERE registration=OLD.name
        AND CASE WHEN json_valid(auth_spec) THEN json_extract(auth_spec,'$.kind')='controlled_oauth' ELSE 0 END
        AND json_extract(auth_spec,'$.incarnation')=OLD.incarnation
        AND json_extract(auth_spec,'$.owner_id')=OLD.owner_id;
END;
