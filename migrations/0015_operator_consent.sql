-- Controlled accounts remain ineligible for legacy agent materialization.
CREATE TEMP TABLE oauth_highwater(value INTEGER NOT NULL);
INSERT INTO oauth_highwater SELECT COALESCE(MAX(seq),0) FROM sqlite_sequence WHERE name='oauth_sessions';
CREATE TABLE oauth_sessions__consent (
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
 CHECK(kind<>'controlled_linear_v1' OR (owner_id IS NOT NULL AND profile_id IS NOT NULL AND profile_digest IS NOT NULL AND workspace_id IS NOT NULL AND user_id IS NOT NULL AND access_token_ciphertext IS NOT NULL AND refresh_pending=0)),
 UNIQUE(name,session_label)
);
INSERT INTO oauth_sessions__consent(incarnation,token_version,name,session_label,refresh_token_ciphertext,refresh_token_nonce,access_token_ciphertext,access_token_nonce,access_token_expires_at,scope,degraded,created_at,updated_at,account_id,refresh_pending)
SELECT incarnation,token_version,name,session_label,refresh_token_ciphertext,refresh_token_nonce,access_token_ciphertext,access_token_nonce,access_token_expires_at,scope,degraded,created_at,updated_at,account_id,refresh_pending FROM oauth_sessions;
DROP TABLE oauth_sessions;
ALTER TABLE oauth_sessions__consent RENAME TO oauth_sessions;
-- INSERT..SELECT created a sequence row even for an empty table; cover either state.
INSERT INTO sqlite_sequence(name,seq) SELECT 'oauth_sessions',value FROM oauth_highwater WHERE NOT EXISTS(SELECT 1 FROM sqlite_sequence WHERE name='oauth_sessions');
UPDATE sqlite_sequence SET seq=MAX(seq,(SELECT value FROM oauth_highwater)) WHERE name='oauth_sessions';
DROP TABLE oauth_highwater;
CREATE INDEX idx_oauth_sessions_refresh_schedule ON oauth_sessions(kind,degraded,access_token_expires_at);

CREATE TABLE oauth_consent_attempts (
 id TEXT PRIMARY KEY, state_hash TEXT UNIQUE, owner_id TEXT NOT NULL,
 name TEXT NOT NULL, session_label TEXT NOT NULL, instance_id TEXT NOT NULL,
 config_revision INTEGER NOT NULL, profile_id TEXT NOT NULL, profile_digest TEXT NOT NULL,
 run_id TEXT NOT NULL, deadline INTEGER NOT NULL, created_at INTEGER NOT NULL,
 updated_at INTEGER NOT NULL, version INTEGER NOT NULL DEFAULT 0,
 state TEXT NOT NULL CHECK(state IN('pending','exchanging','connected','failed','expired','canceled')),
 verifier_ct BLOB, verifier_nonce BLOB, quarantine_ct BLOB, quarantine_nonce BLOB,
 account_generation INTEGER, reason TEXT, stage TEXT NOT NULL DEFAULT 'created', cleanup TEXT, finalization TEXT,
 CHECK((verifier_ct IS NULL)=(verifier_nonce IS NULL)),
 CHECK((quarantine_ct IS NULL)=(quarantine_nonce IS NULL))
);
CREATE UNIQUE INDEX oauth_consent_active ON oauth_consent_attempts(name,session_label) WHERE state IN('pending','exchanging');
CREATE TRIGGER consent_registration_update AFTER UPDATE ON registrations BEGIN UPDATE oauth_consent_attempts SET state='failed', reason='authority_changed', version=version+1, state_hash=NULL, verifier_ct=NULL, verifier_nonce=NULL, quarantine_ct=NULL, quarantine_nonce=NULL WHERE name=OLD.name AND state IN('pending','exchanging'); END;
CREATE TRIGGER consent_registration_delete AFTER DELETE ON registrations BEGIN UPDATE oauth_consent_attempts SET state='failed', reason='authority_changed', version=version+1, state_hash=NULL, verifier_ct=NULL, verifier_nonce=NULL, quarantine_ct=NULL, quarantine_nonce=NULL WHERE name=OLD.name AND state IN('pending','exchanging'); END;
CREATE TRIGGER consent_account_insert AFTER INSERT ON oauth_sessions BEGIN UPDATE oauth_consent_attempts SET state='failed', reason='authority_changed', version=version+1, state_hash=NULL, verifier_ct=NULL, verifier_nonce=NULL, quarantine_ct=NULL, quarantine_nonce=NULL WHERE name=NEW.name AND session_label=NEW.session_label AND state IN('pending','exchanging'); END;
CREATE TRIGGER consent_account_update AFTER UPDATE ON oauth_sessions BEGIN UPDATE oauth_consent_attempts SET state='failed', reason='authority_changed', version=version+1, state_hash=NULL, verifier_ct=NULL, verifier_nonce=NULL, quarantine_ct=NULL, quarantine_nonce=NULL WHERE name=OLD.name AND session_label=OLD.session_label AND state IN('pending','exchanging'); END;
CREATE TRIGGER consent_account_delete AFTER DELETE ON oauth_sessions BEGIN UPDATE oauth_consent_attempts SET state='failed', reason='authority_changed', version=version+1, state_hash=NULL, verifier_ct=NULL, verifier_nonce=NULL, quarantine_ct=NULL, quarantine_nonce=NULL WHERE name=OLD.name AND session_label=OLD.session_label AND state IN('pending','exchanging'); END;
