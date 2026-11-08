-- Declared wire contracts reuse existing custody and sequence authority.
-- Fixed hosted profiles share owner custody, never legacy materialization.
DROP TRIGGER controlled_selection_insert;
DROP TRIGGER controlled_selection_update;
DROP TRIGGER consent_client_retired;
-- Permit committed uncertainty for controlled refresh; preserve all custody.
-- Controlled accounts remain ineligible for legacy agent materialization.
CREATE TEMP TABLE oauth_highwater(value INTEGER NOT NULL);
INSERT INTO oauth_highwater SELECT COALESCE(MAX(seq),0) FROM sqlite_sequence WHERE name='oauth_sessions';
CREATE TABLE oauth_sessions__contract (
 incarnation INTEGER PRIMARY KEY AUTOINCREMENT,
 token_version INTEGER NOT NULL DEFAULT 0 CHECK(typeof(token_version)='integer' AND token_version>=0),
 name TEXT NOT NULL, session_label TEXT NOT NULL DEFAULT 'default',
 refresh_token_ciphertext BLOB, refresh_token_nonce BLOB,
 access_token_ciphertext BLOB, access_token_nonce BLOB, access_token_expires_at INTEGER,
 scope TEXT NOT NULL DEFAULT '', degraded INTEGER NOT NULL DEFAULT 0,
 created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, account_id TEXT,
 refresh_pending INTEGER NOT NULL DEFAULT 0 CHECK(refresh_pending IN(0,1)),
 kind TEXT NOT NULL DEFAULT 'legacy' CHECK(kind IN('legacy','controlled_linear_v1','linear_hosted_v1','linear_hosted_fixture_v1','slack_confidential_v1','slack_confidential_fixture_v1','custom_oauth_v1')),
 owner_id TEXT, profile_id TEXT, profile_digest TEXT, workspace_id TEXT, user_id TEXT,
 scope_echoed INTEGER NOT NULL DEFAULT 0 CHECK(scope_echoed IN(0,1)),
 subject_json TEXT, client_auth TEXT NOT NULL DEFAULT 'none' CHECK(client_auth IN('none','client_secret_post')),
 CHECK((refresh_token_ciphertext IS NULL)=(refresh_token_nonce IS NULL)),
 CHECK((access_token_ciphertext IS NULL)=(access_token_nonce IS NULL)),
 CHECK(kind<>'legacy' OR refresh_token_ciphertext IS NOT NULL),
 CHECK(kind='legacy' OR (owner_id IS NOT NULL AND profile_id IS NOT NULL AND profile_digest IS NOT NULL AND access_token_ciphertext IS NOT NULL)),
 CHECK(kind IN('legacy','custom_oauth_v1') OR (workspace_id IS NOT NULL AND user_id IS NOT NULL)),
 CHECK((kind='custom_oauth_v1')=(subject_json IS NOT NULL)),
 CHECK(kind NOT IN('slack_confidential_v1','slack_confidential_fixture_v1') OR client_auth='client_secret_post'),
 CHECK(kind<>'custom_oauth_v1' OR COALESCE((scope_echoed=1 AND length(scope)>0 AND CASE WHEN json_valid(subject_json) THEN (
   (json_extract(subject_json,'$.kind')='user_workspace' AND json_remove(subject_json,'$.kind','$.workspace_id','$.user_id')='{}'
    AND json_type(subject_json,'$.workspace_id')='text' AND length(json_extract(subject_json,'$.workspace_id')) BETWEEN 1 AND 256
    AND json_type(subject_json,'$.user_id')='text' AND length(json_extract(subject_json,'$.user_id')) BETWEEN 1 AND 256
    AND workspace_id IS json_extract(subject_json,'$.workspace_id') AND user_id IS json_extract(subject_json,'$.user_id'))
   OR (json_extract(subject_json,'$.kind')='service_principal' AND json_remove(subject_json,'$.kind','$.subject_id')='{}'
    AND json_type(subject_json,'$.subject_id')='text' AND length(json_extract(subject_json,'$.subject_id')) BETWEEN 1 AND 256
    AND workspace_id IS NULL AND user_id IS NULL)) ELSE 0 END),0)=1),
 UNIQUE(name,session_label)
);
INSERT INTO oauth_sessions__contract SELECT *,NULL,CASE WHEN kind IN('slack_confidential_v1','slack_confidential_fixture_v1') THEN 'client_secret_post' ELSE 'none' END FROM oauth_sessions;
DROP TABLE oauth_sessions;
ALTER TABLE oauth_sessions__contract RENAME TO oauth_sessions;
-- INSERT..SELECT created a sequence row even for an empty table; cover either state.
INSERT INTO sqlite_sequence(name,seq) SELECT 'oauth_sessions',value FROM oauth_highwater WHERE NOT EXISTS(SELECT 1 FROM sqlite_sequence WHERE name='oauth_sessions');
UPDATE sqlite_sequence SET seq=MAX(seq,(SELECT value FROM oauth_highwater)) WHERE name='oauth_sessions';
DROP TABLE oauth_highwater;
CREATE INDEX idx_oauth_sessions_refresh_schedule ON oauth_sessions(kind,degraded,access_token_expires_at);

CREATE TRIGGER consent_account_insert AFTER INSERT ON oauth_sessions BEGIN UPDATE oauth_consent_attempts SET state='failed', reason='authority_changed', version=version+1, state_hash=NULL, verifier_ct=NULL, verifier_nonce=NULL, quarantine_ct=NULL, quarantine_nonce=NULL WHERE name=NEW.name AND session_label=NEW.session_label AND state IN('pending','exchanging'); END;
CREATE TRIGGER consent_account_update AFTER UPDATE ON oauth_sessions BEGIN UPDATE oauth_consent_attempts SET state='failed', reason='authority_changed', version=version+1, state_hash=NULL, verifier_ct=NULL, verifier_nonce=NULL, quarantine_ct=NULL, quarantine_nonce=NULL WHERE name=OLD.name AND session_label=OLD.session_label AND state IN('pending','exchanging'); END;
CREATE TRIGGER consent_account_delete AFTER DELETE ON oauth_sessions BEGIN UPDATE oauth_consent_attempts SET state='failed', reason='authority_changed', version=version+1, state_hash=NULL, verifier_ct=NULL, verifier_nonce=NULL, quarantine_ct=NULL, quarantine_nonce=NULL WHERE name=OLD.name AND session_label=OLD.session_label AND state IN('pending','exchanging'); END;
CREATE TRIGGER controlled_selection_insert BEFORE INSERT ON agent_credential_overrides
WHEN CASE WHEN json_valid(NEW.auth_spec) THEN json_extract(NEW.auth_spec,'$.kind')='controlled_oauth' ELSE 0 END BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM oauth_sessions o JOIN registrations r ON r.name=o.name
        WHERE o.name=NEW.registration AND o.kind IN ('controlled_linear_v1','linear_hosted_v1','linear_hosted_fixture_v1','slack_confidential_v1','slack_confidential_fixture_v1','custom_oauth_v1')
        AND (o.client_auth='none' OR EXISTS(SELECT 1 FROM oauth_consent_clients c JOIN credential_secrets s USING(secret_ref) WHERE c.owner_id=o.owner_id AND c.profile_id=o.profile_id AND c.profile_digest=o.profile_digest AND c.retired_at IS NULL AND s.tombstoned_at IS NULL))
        AND o.session_label=json_extract(NEW.auth_spec,'$.session_label')
        AND o.owner_id=json_extract(NEW.auth_spec,'$.owner_id')
        AND o.incarnation=json_extract(NEW.auth_spec,'$.incarnation')
        AND json_type(NEW.auth_spec,'$.incarnation')='integer'
        AND o.profile_id=json_extract(NEW.auth_spec,'$.profile_id')
        AND o.profile_digest=json_extract(NEW.auth_spec,'$.profile_digest')
        AND r.kind='tool' AND r.protocol='mcp_streamable_http'
        AND r.disabled=0 AND r.seed=0 AND r.egress='direct'
        AND (json_type(r.mcp_json,'$.definition') IS NULL OR
             (o.kind IN ('controlled_linear_v1','slack_confidential_v1','slack_confidential_fixture_v1','custom_oauth_v1') AND json_extract(r.mcp_json,'$.definition_activation.kind')='controlled_oauth'
              AND json_extract(r.mcp_json,'$.definition_activation.profile_id')=o.profile_id
              AND json_extract(r.mcp_json,'$.definition_activation.profile_digest')=o.profile_digest))
    ) THEN RAISE(ABORT,'controlled_selection_invalid') END;
END;
CREATE TRIGGER controlled_selection_update BEFORE UPDATE OF auth_spec,registration ON agent_credential_overrides
WHEN CASE WHEN json_valid(NEW.auth_spec) THEN json_extract(NEW.auth_spec,'$.kind')='controlled_oauth' ELSE 0 END BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM oauth_sessions o JOIN registrations r ON r.name=o.name
        WHERE o.name=NEW.registration AND o.kind IN ('controlled_linear_v1','linear_hosted_v1','linear_hosted_fixture_v1','slack_confidential_v1','slack_confidential_fixture_v1','custom_oauth_v1')
        AND (o.client_auth='none' OR EXISTS(SELECT 1 FROM oauth_consent_clients c JOIN credential_secrets s USING(secret_ref) WHERE c.owner_id=o.owner_id AND c.profile_id=o.profile_id AND c.profile_digest=o.profile_digest AND c.retired_at IS NULL AND s.tombstoned_at IS NULL))
        AND o.session_label=json_extract(NEW.auth_spec,'$.session_label')
        AND o.owner_id=json_extract(NEW.auth_spec,'$.owner_id')
        AND o.incarnation=json_extract(NEW.auth_spec,'$.incarnation')
        AND json_type(NEW.auth_spec,'$.incarnation')='integer'
        AND o.profile_id=json_extract(NEW.auth_spec,'$.profile_id')
        AND o.profile_digest=json_extract(NEW.auth_spec,'$.profile_digest')
        AND r.kind='tool' AND r.protocol='mcp_streamable_http'
        AND r.disabled=0 AND r.seed=0 AND r.egress='direct'
        AND (json_type(r.mcp_json,'$.definition') IS NULL OR
             (o.kind IN ('controlled_linear_v1','slack_confidential_v1','slack_confidential_fixture_v1','custom_oauth_v1') AND json_extract(r.mcp_json,'$.definition_activation.kind')='controlled_oauth'
              AND json_extract(r.mcp_json,'$.definition_activation.profile_id')=o.profile_id
              AND json_extract(r.mcp_json,'$.definition_activation.profile_digest')=o.profile_digest))
    ) THEN RAISE(ABORT,'controlled_selection_invalid') END;
END;

CREATE TRIGGER controlled_account_deleted AFTER DELETE ON oauth_sessions
WHEN OLD.kind IN ('controlled_linear_v1','linear_hosted_v1','linear_hosted_fixture_v1','slack_confidential_v1','slack_confidential_fixture_v1','custom_oauth_v1') BEGIN
    DELETE FROM agent_credential_overrides WHERE registration=OLD.name
        AND CASE WHEN json_valid(auth_spec) THEN json_extract(auth_spec,'$.kind')='controlled_oauth' ELSE 0 END
        AND json_extract(auth_spec,'$.incarnation')=OLD.incarnation
        AND json_extract(auth_spec,'$.owner_id')=OLD.owner_id;
END;
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
                    (json_extract(p.value,'$.mechanism')='oauth_provider' AND json_type(p.value,'$.required_scopes')='array' AND json_array_length(p.value,'$.required_scopes') BETWEEN 1 AND 32
                     AND NOT EXISTS(SELECT 1 FROM json_each(p.value,'$.required_scopes') WHERE type<>'text' OR length(CAST(value AS BLOB)) NOT BETWEEN 1 AND 128)
                     AND (SELECT count(DISTINCT value) FROM json_each(p.value,'$.required_scopes'))=json_array_length(p.value,'$.required_scopes')
                     AND json_extract(NEW.auth_json,'$.scopes')=json_extract(p.value,'$.required_scopes')
                     AND json_extract(NEW.mcp_json,'$.definition_activation.kind')='controlled_oauth' AND json_extract(NEW.auth_json,'$.kind')='oauth_pkce'
                     AND json_type(NEW.mcp_json,'$.definition_activation.profile_id')='text' AND length(json_extract(NEW.mcp_json,'$.definition_activation.profile_id')) BETWEEN 1 AND 128
                     AND json_type(NEW.mcp_json,'$.definition_activation.profile_digest')='text' AND length(json_extract(NEW.mcp_json,'$.definition_activation.profile_digest'))=43
                     AND (SELECT count(*) FROM json_each(NEW.mcp_json,'$.definition_activation'))=3)
                )
             ))
        ),0) != 1 THEN RAISE(ABORT,'definition_pending') END;
END;


CREATE TRIGGER consent_client_retired AFTER UPDATE OF retired_at ON oauth_consent_clients BEGIN
 UPDATE oauth_consent_attempts SET state='failed',reason='client_retired',version=version+1,state_hash=NULL,verifier_ct=NULL,verifier_nonce=NULL,quarantine_ct=NULL,quarantine_nonce=NULL
 WHERE owner_id=OLD.owner_id AND profile_id=OLD.profile_id AND profile_digest=OLD.profile_digest AND state IN ('pending','exchanging');
 UPDATE oauth_sessions SET degraded=1,token_version=CASE WHEN token_version<9223372036854775806 THEN token_version+1 ELSE token_version END
 WHERE owner_id=OLD.owner_id AND profile_id=OLD.profile_id AND profile_digest=OLD.profile_digest;
END;
