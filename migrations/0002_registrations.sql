-- Phase E (v2.0.0) — kind-discriminated registrations.
--
-- Replaces the pre-Phase-E config.tools YAML-only catalog with a
-- DB-backed registrations table. Seed catalog populates first-boot;
-- operator overrides via admin API. See:
--   agents-stack/docs/spec/v0.2.0.md (forthcoming)
--   agents-stack/docs/plans/2026-05-06-v2.0.0-catalog-seed.md
--
-- Forward-only per INF-11. Pre-Phase-E deployments had no `tools` table
-- (tools lived in YAML config), so no data migration is needed at the
-- SQL layer. The bootstrap-from-yaml shim in src/daemon.rs (E.7) reads
-- legacy `tools/*.yaml` once and writes operator-override rows
-- (seed=0) into registrations; deprecated in v2.0.0, removed in v0.3.

CREATE TABLE registrations (
    name             TEXT NOT NULL PRIMARY KEY,
    kind             TEXT NOT NULL CHECK (kind IN ('model', 'tool', 'infra')),
    description      TEXT NOT NULL DEFAULT '',
    upstream         TEXT NOT NULL,
    -- AuthSpec serialized as JSON. {"kind":"none"} for authless,
    -- {"kind":"header","header":...,"env_var":...} for header injection,
    -- {"kind":"bearer","env_var":...} for Authorization: Bearer.
    auth_json        TEXT NOT NULL,
    egress           TEXT NOT NULL DEFAULT 'proxied' CHECK (egress IN ('direct', 'proxied')),
    -- ToolTimeouts as JSON: {"request_seconds":N,"idle_seconds":N}.
    timeouts_json    TEXT NOT NULL,
    body_limit_bytes INTEGER NOT NULL DEFAULT 10485760,
    -- Per-kind metadata as JSON object. modality/provider for kind=model,
    -- capability/provider for kind=tool, role/internal_token_env for kind=infra.
    metadata_json    TEXT NOT NULL DEFAULT '{}',
    -- Lifecycle: seed=1 means loaded from /etc/locksmith/seed/catalog.yaml.
    -- Operator override flips seed=0 (image upgrades preserve overrides).
    seed             INTEGER NOT NULL DEFAULT 0,
    -- Operator-disabled. Sticky across image upgrades. Filtered out of
    -- discovery + ACL resolution but row stays in DB.
    disabled         INTEGER NOT NULL DEFAULT 0,
    created_at       INTEGER NOT NULL,
    updated_at       INTEGER NOT NULL
);

CREATE INDEX idx_registrations_kind ON registrations(kind);
CREATE INDEX idx_registrations_seed_disabled ON registrations(seed, disabled);

-- Single-row metadata table for the seed catalog version. Generic key/value
-- so future bookkeeping (catalog source URL, last-loaded timestamp, etc.)
-- doesn't require a schema bump.
CREATE TABLE registrations_meta (
    key   TEXT NOT NULL PRIMARY KEY,
    value TEXT NOT NULL
);
