-- Fixed hosted profiles share owner custody, never legacy materialization.
DROP TRIGGER controlled_selection_insert;
DROP TRIGGER controlled_selection_update;
-- Permit committed uncertainty for controlled refresh; preserve all custody.
-- Controlled accounts remain ineligible for legacy agent materialization.
CREATE TEMP TABLE oauth_highwater(value INTEGER NOT NULL);
INSERT INTO oauth_highwater SELECT COALESCE(MAX(seq),0) FROM sqlite_sequence WHERE name='oauth_sessions';
CREATE TABLE oauth_sessions__hosted (
 incarnation INTEGER PRIMARY KEY AUTOINCREMENT,
 token_version INTEGER NOT NULL DEFAULT 0 CHECK(typeof(token_version)='integer' AND token_version>=0),
 name TEXT NOT NULL, session_label TEXT NOT NULL DEFAULT 'default',
 refresh_token_ciphertext BLOB, refresh_token_nonce BLOB,
 access_token_ciphertext BLOB, access_token_nonce BLOB, access_token_expires_at INTEGER,
 scope TEXT NOT NULL DEFAULT '', degraded INTEGER NOT NULL DEFAULT 0,
 created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, account_id TEXT,
 refresh_pending INTEGER NOT NULL DEFAULT 0 CHECK(refresh_pending IN(0,1)),
 kind TEXT NOT NULL DEFAULT 'legacy' CHECK(kind IN('legacy','controlled_linear_v1','linear_hosted_v1','linear_hosted_fixture_v1')),
 owner_id TEXT, profile_id TEXT, profile_digest TEXT, workspace_id TEXT, user_id TEXT,
 scope_echoed INTEGER NOT NULL DEFAULT 0 CHECK(scope_echoed IN(0,1)),
 CHECK((refresh_token_ciphertext IS NULL)=(refresh_token_nonce IS NULL)),
 CHECK((access_token_ciphertext IS NULL)=(access_token_nonce IS NULL)),
 CHECK(kind<>'legacy' OR refresh_token_ciphertext IS NOT NULL),
 CHECK(kind='legacy' OR (owner_id IS NOT NULL AND profile_id IS NOT NULL AND profile_digest IS NOT NULL AND workspace_id IS NOT NULL AND user_id IS NOT NULL AND access_token_ciphertext IS NOT NULL)),
 UNIQUE(name,session_label)
);
INSERT INTO oauth_sessions__hosted SELECT * FROM oauth_sessions;
DROP TABLE oauth_sessions;
ALTER TABLE oauth_sessions__hosted RENAME TO oauth_sessions;
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
        WHERE o.name=NEW.registration AND o.kind IN ('controlled_linear_v1','linear_hosted_v1','linear_hosted_fixture_v1')
        AND o.session_label=json_extract(NEW.auth_spec,'$.session_label')
        AND o.owner_id=json_extract(NEW.auth_spec,'$.owner_id')
        AND o.incarnation=json_extract(NEW.auth_spec,'$.incarnation')
        AND json_type(NEW.auth_spec,'$.incarnation')='integer'
        AND o.profile_id=json_extract(NEW.auth_spec,'$.profile_id')
        AND o.profile_digest=json_extract(NEW.auth_spec,'$.profile_digest')
        AND r.kind='tool' AND r.protocol='mcp_streamable_http'
        AND r.disabled=0 AND r.seed=0 AND r.egress='direct'
        AND (json_type(r.mcp_json,'$.definition') IS NULL OR
             (o.kind='controlled_linear_v1' AND json_extract(r.mcp_json,'$.definition_activation.kind')='controlled_oauth'
              AND json_extract(r.mcp_json,'$.definition_activation.profile_id')=o.profile_id
              AND json_extract(r.mcp_json,'$.definition_activation.profile_digest')=o.profile_digest))
    ) THEN RAISE(ABORT,'controlled_selection_invalid') END;
END;
CREATE TRIGGER controlled_selection_update BEFORE UPDATE OF auth_spec,registration ON agent_credential_overrides
WHEN CASE WHEN json_valid(NEW.auth_spec) THEN json_extract(NEW.auth_spec,'$.kind')='controlled_oauth' ELSE 0 END BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM oauth_sessions o JOIN registrations r ON r.name=o.name
        WHERE o.name=NEW.registration AND o.kind IN ('controlled_linear_v1','linear_hosted_v1','linear_hosted_fixture_v1')
        AND o.session_label=json_extract(NEW.auth_spec,'$.session_label')
        AND o.owner_id=json_extract(NEW.auth_spec,'$.owner_id')
        AND o.incarnation=json_extract(NEW.auth_spec,'$.incarnation')
        AND json_type(NEW.auth_spec,'$.incarnation')='integer'
        AND o.profile_id=json_extract(NEW.auth_spec,'$.profile_id')
        AND o.profile_digest=json_extract(NEW.auth_spec,'$.profile_digest')
        AND r.kind='tool' AND r.protocol='mcp_streamable_http'
        AND r.disabled=0 AND r.seed=0 AND r.egress='direct'
        AND (json_type(r.mcp_json,'$.definition') IS NULL OR
             (o.kind='controlled_linear_v1' AND json_extract(r.mcp_json,'$.definition_activation.kind')='controlled_oauth'
              AND json_extract(r.mcp_json,'$.definition_activation.profile_id')=o.profile_id
              AND json_extract(r.mcp_json,'$.definition_activation.profile_digest')=o.profile_digest))
    ) THEN RAISE(ABORT,'controlled_selection_invalid') END;
END;

CREATE TRIGGER controlled_account_deleted AFTER DELETE ON oauth_sessions
WHEN OLD.kind IN ('controlled_linear_v1','linear_hosted_v1','linear_hosted_fixture_v1') BEGIN
    DELETE FROM agent_credential_overrides WHERE registration=OLD.name
        AND CASE WHEN json_valid(auth_spec) THEN json_extract(auth_spec,'$.kind')='controlled_oauth' ELSE 0 END
        AND json_extract(auth_spec,'$.incarnation')=OLD.incarnation
        AND json_extract(auth_spec,'$.owner_id')=OLD.owner_id;
END;
