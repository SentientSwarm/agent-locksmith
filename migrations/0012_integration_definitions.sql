-- Offline immutable authoring. No authority or credential defaults are copied.
CREATE TABLE integration_definitions (
    id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK(revision BETWEEN 1 AND 2147483647),
    canonical_json TEXT NOT NULL CHECK(json_valid(canonical_json)),
    digest TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY(id, revision)
);
CREATE TRIGGER integration_definitions_no_update BEFORE UPDATE ON integration_definitions
BEGIN SELECT RAISE(ABORT, 'definition_immutable'); END;
CREATE TRIGGER integration_definitions_no_delete BEFORE DELETE ON integration_definitions
BEGIN SELECT RAISE(ABORT, 'definition_immutable'); END;

-- Reject malformed/null pins, including SQL NULL comparisons, before insertion.
CREATE TRIGGER registration_definition_insert BEFORE INSERT ON registrations
WHEN json_type(NEW.mcp_json, '$.definition') IS NOT NULL
BEGIN
    SELECT CASE WHEN COALESCE(
        NEW.disabled = 1 AND NEW.seed = 0 AND NEW.kind = 'tool'
        AND NEW.protocol = 'mcp_streamable_http' AND NEW.egress = 'direct'
        AND NEW.auth_json = '{"kind":"none"}'
        AND json_type(NEW.mcp_json, '$.definition') = 'object'
        AND (SELECT count(*) FROM json_each(NEW.mcp_json, '$.definition')) = 4
        AND json_type(NEW.mcp_json, '$.definition.id') = 'text'
        AND json_type(NEW.mcp_json, '$.definition.revision') = 'integer'
        AND json_type(NEW.mcp_json, '$.definition.digest') = 'text'
        AND json_type(NEW.mcp_json, '$.definition.auth_profile_id') = 'text'
        AND EXISTS (
            SELECT 1 FROM integration_definitions d, json_each(d.canonical_json, '$.auth_profiles') p
            WHERE d.id = json_extract(NEW.mcp_json, '$.definition.id')
              AND d.revision = json_extract(NEW.mcp_json, '$.definition.revision')
              AND d.digest = json_extract(NEW.mcp_json, '$.definition.digest')
              AND json_extract(p.value, '$.id') = json_extract(NEW.mcp_json, '$.definition.auth_profile_id')
        ), 0) != 1 THEN RAISE(ABORT, 'definition_pending') END;
END;
-- All edits to derived rows (including pin stripping) await promotion contracts.
-- Also reject adding a pin via UPDATE: only the create-only route can derive rows.
CREATE TRIGGER registration_definition_update BEFORE UPDATE ON registrations
WHEN json_type(OLD.mcp_json, '$.definition') IS NOT NULL
  OR json_type(NEW.mcp_json, '$.definition') IS NOT NULL
BEGIN SELECT RAISE(ABORT, 'definition_pending'); END;
