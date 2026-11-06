-- Forward-only correction: policy/selection are dedicated activation state.
-- Preserve exact pins, active no-change and deactivation reset; rewrite no rows.
DROP TRIGGER registration_definition_update;
CREATE TRIGGER registration_definition_update BEFORE UPDATE ON registrations
WHEN json_type(OLD.mcp_json,'$.definition') IS NOT NULL OR json_type(NEW.mcp_json,'$.definition') IS NOT NULL BEGIN
    SELECT CASE WHEN COALESCE(
        json_type(OLD.mcp_json,'$.definition')='object'
        AND json_extract(NEW.mcp_json,'$.definition')=json_extract(OLD.mcp_json,'$.definition')
        AND NEW.name=OLD.name AND NEW.kind=OLD.kind AND NEW.description=OLD.description
        AND NEW.upstream=OLD.upstream AND NEW.egress=OLD.egress AND NEW.timeouts_json=OLD.timeouts_json
        AND NEW.body_limit_bytes=OLD.body_limit_bytes AND NEW.metadata_json=OLD.metadata_json
        AND NEW.seed=OLD.seed AND NEW.created_at=OLD.created_at AND NEW.protocol=OLD.protocol
        AND json_remove(NEW.mcp_json,'$.definition_activation','$.compact','$.contract_policy','$.selected_tools')=json_remove(OLD.mcp_json,'$.definition_activation','$.compact','$.contract_policy','$.selected_tools')
        AND (json_extract(NEW.mcp_json,'$.compact') IN (0,1) OR json_type(NEW.mcp_json,'$.compact') IS NULL)
        AND (json_type(NEW.mcp_json,'$.contract_policy') IS NULL
             OR json_extract(NEW.mcp_json,'$.contract_policy')='finite-v2')
        AND (json_type(NEW.mcp_json,'$.selected_tools') IS NULL OR (
            json_extract(NEW.mcp_json,'$.contract_policy')='finite-v2'
            AND json_type(NEW.mcp_json,'$.selected_tools')='array'
            AND json_array_length(NEW.mcp_json,'$.selected_tools') BETWEEN 1 AND 32
            AND NOT EXISTS (SELECT 1 FROM json_each(NEW.mcp_json,'$.selected_tools')
                WHERE type!='text' OR length(CAST(value AS BLOB)) NOT BETWEEN 1 AND 128)
            AND (SELECT count(DISTINCT value) FROM json_each(NEW.mcp_json,'$.selected_tools'))
                =json_array_length(NEW.mcp_json,'$.selected_tools')
        ))
        AND (
            (NEW.disabled=1 AND NEW.auth_json='{"kind":"none"}' AND json_type(NEW.mcp_json,'$.definition_activation') IS NULL
             AND json_type(NEW.mcp_json,'$.contract_policy') IS NULL
             AND json_type(NEW.mcp_json,'$.selected_tools') IS NULL
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
