-- Operator preparation only. This migration creates no callable authority.
CREATE TABLE native_observations (
    instance TEXT NOT NULL REFERENCES registration_instances(instance_id) ON DELETE CASCADE,
    account_key TEXT NOT NULL,
    generation TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('pending','failed','ready')),
    run_id TEXT NOT NULL,
    registration_revision INTEGER NOT NULL,
    observed_at INTEGER,
    manifest TEXT,
    PRIMARY KEY(instance, account_key)
);
CREATE TABLE native_reviews (
    instance TEXT NOT NULL REFERENCES registration_instances(instance_id) ON DELETE CASCADE,
    account_key TEXT NOT NULL,
    name TEXT NOT NULL,
    contract_digest TEXT NOT NULL,
    observed_digest TEXT NOT NULL,
    contract TEXT NOT NULL,
    PRIMARY KEY(instance, account_key, name, contract_digest)
);
CREATE TRIGGER native_review_immutable BEFORE UPDATE ON native_reviews BEGIN
    SELECT RAISE(ABORT, 'native_review_immutable');
END;
CREATE TABLE native_grant_sets (
    agent_id INTEGER NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    instance TEXT NOT NULL REFERENCES registration_instances(instance_id) ON DELETE CASCADE,
    revision TEXT NOT NULL,
    PRIMARY KEY(agent_id, instance)
);
CREATE TABLE native_tool_grants (
    agent_id INTEGER NOT NULL,
    instance TEXT NOT NULL,
    account_key TEXT NOT NULL,
    name TEXT NOT NULL,
    contract_digest TEXT NOT NULL,
    PRIMARY KEY(agent_id, instance, name),
    FOREIGN KEY(agent_id,instance) REFERENCES native_grant_sets(agent_id,instance) ON DELETE CASCADE,
    FOREIGN KEY(instance,account_key,name,contract_digest)
        REFERENCES native_reviews(instance,account_key,name,contract_digest) ON DELETE CASCADE
);
CREATE TRIGGER native_grant_binding_deleted AFTER DELETE ON agent_credential_overrides BEGIN
    DELETE FROM native_tool_grants WHERE agent_id=OLD.agent_id AND instance IN
        (SELECT instance_id FROM registration_instances WHERE name=OLD.registration);
    UPDATE native_grant_sets SET revision=lower(hex(randomblob(16)))
        WHERE agent_id=OLD.agent_id AND instance IN
        (SELECT instance_id FROM registration_instances WHERE name=OLD.registration);
END;
CREATE TRIGGER native_grant_binding_changed AFTER UPDATE OF auth_spec ON agent_credential_overrides
WHEN CASE WHEN json_valid(OLD.auth_spec) AND json_valid(NEW.auth_spec)
    THEN json(OLD.auth_spec) != json(NEW.auth_spec)
    ELSE OLD.auth_spec IS NOT NEW.auth_spec END BEGIN
    DELETE FROM native_tool_grants WHERE agent_id=NEW.agent_id AND instance IN
        (SELECT instance_id FROM registration_instances WHERE name=NEW.registration);
    UPDATE native_grant_sets SET revision=lower(hex(randomblob(16)))
        WHERE agent_id=NEW.agent_id AND instance IN
        (SELECT instance_id FROM registration_instances WHERE name=NEW.registration);
END;
CREATE TRIGGER native_preparation_destination_changed
AFTER UPDATE OF upstream,egress,protocol,mcp_json ON registrations
WHEN OLD.upstream != NEW.upstream OR OLD.egress != NEW.egress
  OR OLD.protocol != NEW.protocol OR OLD.mcp_json IS NOT NEW.mcp_json BEGIN
    DELETE FROM native_observations WHERE instance IN
        (SELECT instance_id FROM registration_instances WHERE name=NEW.name);
    DELETE FROM native_reviews WHERE instance IN
        (SELECT instance_id FROM registration_instances WHERE name=NEW.name);
    UPDATE native_grant_sets SET revision=lower(hex(randomblob(16))) WHERE instance IN
        (SELECT instance_id FROM registration_instances WHERE name=NEW.name);
END;
