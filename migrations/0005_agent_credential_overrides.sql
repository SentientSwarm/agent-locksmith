-- Phase G (v2.0.0): Per-agent credential overrides.
--
-- An override row binds (agent_id, registration) → AuthSpec, allowing
-- a specific agent to use a different upstream credential than the
-- registration's default. Three concrete uses:
--
--   1. Per-agent header/bearer: override resolves a different env var
--      so each agent presents a distinct API key upstream
--      (e.g., LM_STUDIO_API_KEY_HERMES vs LM_STUDIO_API_KEY_OPENCLAW).
--      Provider dashboards can then attribute usage and quota per
--      agent.
--
--   2. Per-agent OAuth label: override carries a session_label so the
--      proxy resolves a distinct oauth_sessions row per agent
--      (e.g., codex/"hermes" vs codex/"openclaw"). Each agent uses its
--      own ChatGPT subscription / refresh token.
--
--   3. Per-agent override of `auth: none` to require auth (or vice
--      versa). Edge case but the schema permits it.
--
-- Resolution order on the proxy hot path (src/proxy.rs):
--   1. catalog.lookup_active(name)             → registration default
--   2. agent_credential_overrides[agent, name] → override (if any)
--   3. effective_auth = override.unwrap_or(registration.default)
--
-- The override's auth_spec is always a complete AuthSpec — never a
-- partial diff. This keeps resolution simple and avoids schema-
-- migration drift if AuthSpec gains fields. Storage cost is small
-- (≤ ~256 bytes per override row in the typical case).

CREATE TABLE agent_credential_overrides (
    -- FK to agents.id (the integer PK, not public_id). ON DELETE
    -- CASCADE ensures override rows vanish when an agent is hard-
    -- deleted. Soft-delete (revoke) does NOT touch overrides — the
    -- audit row should still link the override that was active at
    -- request time.
    agent_id        INTEGER NOT NULL,

    -- Registration name. Plain TEXT (no FK enforcement; SQLite would
    -- need PRAGMA foreign_keys=ON which we don't currently set
    -- universally). RegistrationRepository writes are gated through
    -- the admin layer, which validates the name exists before
    -- accepting the override.
    registration    TEXT NOT NULL,

    -- AuthSpec serialized as JSON, identical shape to
    -- registrations.auth_json. Variants:
    --   {"kind":"none"}
    --   {"kind":"header","header":"x-api-key","env_var":"FOO"}
    --   {"kind":"bearer","env_var":"FOO"}
    --   {"kind":"oauth_pkce", ...,"session_label":"hermes"}
    --   {"kind":"oauth_device_code", ...,"session_label":"hermes"}
    --
    -- The session_label key is OPTIONAL on OAuth variants and only
    -- meaningful for them. Absence == "default". Validation lives in
    -- the AuthSpec deserializer and the admin set-credential path.
    auth_spec       TEXT NOT NULL,

    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL,

    PRIMARY KEY (agent_id, registration),
    FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE CASCADE
);

-- Hot-path lookup is by (agent_id, registration) — the PK already
-- supports it. No extra index required.
