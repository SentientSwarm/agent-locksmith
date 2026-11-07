-- Dedicated definition activation creates no account or grant. Exact pins remain immutable.
-- Generic writers remain refused in application transactions; SQL constrains all transitions.
DROP TRIGGER registration_definition_update;
CREATE TRIGGER registration_activation_insert BEFORE INSERT ON registrations
WHEN json_type(NEW.mcp_json,'$.definition_activation') IS NOT NULL BEGIN
    SELECT RAISE(ABORT,'definition_pending');
END;
CREATE TRIGGER registration_manual_activation_update BEFORE UPDATE ON registrations
WHEN json_type(OLD.mcp_json,'$.definition') IS NULL AND json_type(NEW.mcp_json,'$.definition_activation') IS NOT NULL BEGIN
    SELECT RAISE(ABORT,'definition_pending');
END;
CREATE TRIGGER registration_definition_update BEFORE UPDATE ON registrations
WHEN json_type(OLD.mcp_json,'$.definition') IS NOT NULL OR json_type(NEW.mcp_json,'$.definition') IS NOT NULL BEGIN
    SELECT CASE WHEN COALESCE(
        json_type(OLD.mcp_json,'$.definition')='object'
        AND json_extract(NEW.mcp_json,'$.definition')=json_extract(OLD.mcp_json,'$.definition')
        AND NEW.name=OLD.name AND NEW.kind=OLD.kind AND NEW.description=OLD.description
        AND NEW.upstream=OLD.upstream AND NEW.egress=OLD.egress AND NEW.timeouts_json=OLD.timeouts_json
        AND NEW.body_limit_bytes=OLD.body_limit_bytes AND NEW.metadata_json=OLD.metadata_json
        AND NEW.seed=OLD.seed AND NEW.created_at=OLD.created_at AND NEW.protocol=OLD.protocol
        AND json_remove(NEW.mcp_json,'$.definition_activation','$.compact')=json_remove(OLD.mcp_json,'$.definition_activation','$.compact')
        AND (json_extract(NEW.mcp_json,'$.compact') IN (0,1) OR json_type(NEW.mcp_json,'$.compact') IS NULL)
        AND (
            (NEW.disabled=1 AND NEW.auth_json='{"kind":"none"}' AND json_type(NEW.mcp_json,'$.definition_activation') IS NULL
             AND COALESCE(json_extract(NEW.mcp_json,'$.compact'),0)=COALESCE(json_extract(OLD.mcp_json,'$.compact'),0))
            OR
            (NEW.disabled=0 AND NEW.seed=0 AND NEW.kind='tool' AND NEW.protocol='mcp_streamable_http' AND NEW.egress='direct'
             AND json_type(NEW.mcp_json,'$.definition_activation')='object'
             AND (json_type(OLD.mcp_json,'$.definition_activation') IS NULL OR (NEW.mcp_json=OLD.mcp_json AND NEW.auth_json=OLD.auth_json AND NEW.disabled=OLD.disabled))
             AND EXISTS (
                SELECT 1 FROM integration_definitions d, json_each(d.canonical_json,'$.auth_profiles') p
                WHERE d.id=json_extract(NEW.mcp_json,'$.definition.id') AND substr(d.id,1,6)='local.'
                AND d.revision=json_extract(NEW.mcp_json,'$.definition.revision') AND d.digest=json_extract(NEW.mcp_json,'$.definition.digest')
                AND json_extract(p.value,'$.id')=json_extract(NEW.mcp_json,'$.definition.auth_profile_id')
                AND (
                    (json_extract(p.value,'$.mechanism')='none' AND json_array_length(p.value,'$.required_scopes')=0
                     AND json_extract(NEW.mcp_json,'$.definition_activation.kind')='none' AND NEW.auth_json='{"kind":"none"}'
                     AND (SELECT count(*) FROM json_each(NEW.mcp_json,'$.definition_activation'))=1)
                    OR
                    (json_extract(p.value,'$.mechanism')='bearer' AND json_array_length(p.value,'$.required_scopes')=0
                     AND json_extract(NEW.mcp_json,'$.definition_activation.kind')='stored_bearer' AND NEW.auth_json='{"kind":"none"}'
                     AND (SELECT count(*) FROM json_each(NEW.mcp_json,'$.definition_activation'))=1)
                    OR
                    (json_extract(p.value,'$.mechanism')='oauth_provider' AND json_extract(p.value,'$.required_scopes')='["read"]'
                     AND json_extract(NEW.mcp_json,'$.definition_activation.kind')='controlled_oauth' AND json_extract(NEW.auth_json,'$.kind')='oauth_pkce'
                     AND json_type(NEW.mcp_json,'$.definition_activation.profile_id')='text' AND length(json_extract(NEW.mcp_json,'$.definition_activation.profile_id')) BETWEEN 1 AND 128
                     AND json_type(NEW.mcp_json,'$.definition_activation.profile_digest')='text' AND length(json_extract(NEW.mcp_json,'$.definition_activation.profile_digest'))=43
                     AND (SELECT count(*) FROM json_each(NEW.mcp_json,'$.definition_activation'))=3)
                )
             ))
        ),0) != 1 THEN RAISE(ABORT,'definition_pending') END;
END;
-- No generic upsert can reauthor a pin, even if it happens to supply equal values.
CREATE TRIGGER registration_definition_generic_update BEFORE UPDATE OF name,kind,description,upstream,egress,timeouts_json,body_limit_bytes,metadata_json,seed,created_at,protocol ON registrations
WHEN json_type(OLD.mcp_json,'$.definition') IS NOT NULL BEGIN
    SELECT RAISE(ABORT,'definition_pending');
END;

DROP TRIGGER controlled_selection_insert;
DROP TRIGGER controlled_selection_update;
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
        AND (json_type(r.mcp_json,'$.definition') IS NULL OR
             (json_extract(r.mcp_json,'$.definition_activation.kind')='controlled_oauth'
              AND json_extract(r.mcp_json,'$.definition_activation.profile_id')=o.profile_id
              AND json_extract(r.mcp_json,'$.definition_activation.profile_digest')=o.profile_digest))
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
        AND (json_type(r.mcp_json,'$.definition') IS NULL OR
             (json_extract(r.mcp_json,'$.definition_activation.kind')='controlled_oauth'
              AND json_extract(r.mcp_json,'$.definition_activation.profile_id')=o.profile_id
              AND json_extract(r.mcp_json,'$.definition_activation.profile_digest')=o.profile_digest))
    ) THEN RAISE(ABORT,'controlled_selection_invalid') END;
END;

CREATE TRIGGER definition_selection_insert BEFORE INSERT ON agent_credential_overrides
WHEN EXISTS(SELECT 1 FROM registrations WHERE name=NEW.registration AND json_type(mcp_json,'$.definition') IS NOT NULL) BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM registrations r WHERE r.name=NEW.registration AND r.disabled=0 AND (
            (json_extract(r.mcp_json,'$.definition_activation.kind')='none' AND json_extract(NEW.auth_spec,'$.kind')='none')
            OR (json_extract(r.mcp_json,'$.definition_activation.kind')='stored_bearer' AND json_extract(NEW.auth_spec,'$.kind')='stored_bearer'
                AND EXISTS(SELECT 1 FROM credential_secrets s WHERE s.secret_ref=json_extract(NEW.auth_spec,'$.secret_ref') AND s.tombstoned_at IS NULL))
            OR (json_extract(r.mcp_json,'$.definition_activation.kind')='controlled_oauth' AND json_extract(NEW.auth_spec,'$.kind')='controlled_oauth'
                AND json_extract(r.mcp_json,'$.definition_activation.profile_id')=json_extract(NEW.auth_spec,'$.profile_id')
                AND json_extract(r.mcp_json,'$.definition_activation.profile_digest')=json_extract(NEW.auth_spec,'$.profile_digest'))
        )
    ) THEN RAISE(ABORT,'definition_selection_invalid') END;
END;

CREATE TRIGGER definition_selection_update BEFORE UPDATE OF auth_spec,registration ON agent_credential_overrides
WHEN EXISTS(SELECT 1 FROM registrations WHERE name=NEW.registration AND json_type(mcp_json,'$.definition') IS NOT NULL) BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM registrations r WHERE r.name=NEW.registration AND r.disabled=0 AND (
            (json_extract(r.mcp_json,'$.definition_activation.kind')='none' AND json_extract(NEW.auth_spec,'$.kind')='none')
            OR (json_extract(r.mcp_json,'$.definition_activation.kind')='stored_bearer' AND json_extract(NEW.auth_spec,'$.kind')='stored_bearer'
                AND EXISTS(SELECT 1 FROM credential_secrets s WHERE s.secret_ref=json_extract(NEW.auth_spec,'$.secret_ref') AND s.tombstoned_at IS NULL))
            OR (json_extract(r.mcp_json,'$.definition_activation.kind')='controlled_oauth' AND json_extract(NEW.auth_spec,'$.kind')='controlled_oauth'
                AND json_extract(r.mcp_json,'$.definition_activation.profile_id')=json_extract(NEW.auth_spec,'$.profile_id')
                AND json_extract(r.mcp_json,'$.definition_activation.profile_digest')=json_extract(NEW.auth_spec,'$.profile_digest'))
        )
    ) THEN RAISE(ABORT,'definition_selection_invalid') END;
END;
