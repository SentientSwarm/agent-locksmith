-- Permit committed uncertainty for controlled refresh; preserve all custody.
-- Controlled accounts remain ineligible for legacy agent materialization.
CREATE TEMP TABLE oauth_highwater(value INTEGER NOT NULL);
INSERT INTO oauth_highwater SELECT COALESCE(MAX(seq),0) FROM sqlite_sequence WHERE name='oauth_sessions';
CREATE TABLE oauth_sessions__refresh (
 incarnation INTEGER PRIMARY KEY AUTOINCREMENT,
 token_version INTEGER NOT NULL DEFAULT 0 CHECK(typeof(token_version)='integer' AND token_version>=0),
 name TEXT NOT NULL, session_label TEXT NOT NULL DEFAULT 'default',
 refresh_token_ciphertext BLOB, refresh_token_nonce BLOB,
 access_token_ciphertext BLOB, access_token_nonce BLOB, access_token_expires_at INTEGER,
 scope TEXT NOT NULL DEFAULT '', degraded INTEGER NOT NULL DEFAULT 0,
 created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, account_id TEXT,
 refresh_pending INTEGER NOT NULL DEFAULT 0 CHECK(refresh_pending IN(0,1)),
 kind TEXT NOT NULL DEFAULT 'legacy' CHECK(kind IN('legacy','controlled_linear_v1')),
 owner_id TEXT, profile_id TEXT, profile_digest TEXT, workspace_id TEXT, user_id TEXT,
 scope_echoed INTEGER NOT NULL DEFAULT 0 CHECK(scope_echoed IN(0,1)),
 CHECK((refresh_token_ciphertext IS NULL)=(refresh_token_nonce IS NULL)),
 CHECK((access_token_ciphertext IS NULL)=(access_token_nonce IS NULL)),
 CHECK(kind<>'legacy' OR refresh_token_ciphertext IS NOT NULL),
 CHECK(kind<>'controlled_linear_v1' OR (owner_id IS NOT NULL AND profile_id IS NOT NULL AND profile_digest IS NOT NULL AND workspace_id IS NOT NULL AND user_id IS NOT NULL AND access_token_ciphertext IS NOT NULL)),
 UNIQUE(name,session_label)
);
INSERT INTO oauth_sessions__refresh SELECT * FROM oauth_sessions;
DROP TABLE oauth_sessions;
ALTER TABLE oauth_sessions__refresh RENAME TO oauth_sessions;
-- INSERT..SELECT created a sequence row even for an empty table; cover either state.
INSERT INTO sqlite_sequence(name,seq) SELECT 'oauth_sessions',value FROM oauth_highwater WHERE NOT EXISTS(SELECT 1 FROM sqlite_sequence WHERE name='oauth_sessions');
UPDATE sqlite_sequence SET seq=MAX(seq,(SELECT value FROM oauth_highwater)) WHERE name='oauth_sessions';
DROP TABLE oauth_highwater;
CREATE INDEX idx_oauth_sessions_refresh_schedule ON oauth_sessions(kind,degraded,access_token_expires_at);

CREATE TRIGGER consent_account_insert AFTER INSERT ON oauth_sessions BEGIN UPDATE oauth_consent_attempts SET state='failed', reason='authority_changed', version=version+1, state_hash=NULL, verifier_ct=NULL, verifier_nonce=NULL, quarantine_ct=NULL, quarantine_nonce=NULL WHERE name=NEW.name AND session_label=NEW.session_label AND state IN('pending','exchanging'); END;
CREATE TRIGGER consent_account_update AFTER UPDATE ON oauth_sessions BEGIN UPDATE oauth_consent_attempts SET state='failed', reason='authority_changed', version=version+1, state_hash=NULL, verifier_ct=NULL, verifier_nonce=NULL, quarantine_ct=NULL, quarantine_nonce=NULL WHERE name=OLD.name AND session_label=OLD.session_label AND state IN('pending','exchanging'); END;
CREATE TRIGGER consent_account_delete AFTER DELETE ON oauth_sessions BEGIN UPDATE oauth_consent_attempts SET state='failed', reason='authority_changed', version=version+1, state_hash=NULL, verifier_ct=NULL, verifier_nonce=NULL, quarantine_ct=NULL, quarantine_nonce=NULL WHERE name=OLD.name AND session_label=OLD.session_label AND state IN('pending','exchanging'); END;
