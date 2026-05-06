//! First-boot loader for the seed catalog (`/etc/locksmith/seed/catalog.yaml`).
//!
//! Phase E.7. Runs in `daemon.rs` immediately after migrations open
//! the SQLite pool and before bind/listen.
//!
//! Idempotent: comparing `catalog.version` against
//! `registrations_meta.seed_version`:
//! - Equal → no-op.
//! - Catalog newer → INSERT new entries with seed=1; UPDATE existing
//!   seed=1 rows where catalog fields changed; SKIP seed=0 rows
//!   (operator-overridden — preserves operator's wire shape across
//!   image upgrades).
//! - Catalog older → log WARN, do nothing (downgrade-safe).
//!
//! Validation runs at load time as if each entry were an admin PUT.
//! A malformed catalog (charset / reserved name / cross-kind reuse /
//! kind=tool or kind=model without `auth:` field) ABORTS startup —
//! the catalog ships with the image, so a bad catalog is an image
//! build bug. (`auth: none` IS accepted on kind=model — see api.rs
//! for the LAN-local-inference rationale.)

use crate::config::{EgressMode, ToolTimeouts};
use crate::registrations::{
    AuthSpec, Kind, Registration, RegistrationError, RegistrationRepository, validate_name,
};
use serde::Deserialize;
use serde_json::Value as Json;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

/// Default seed-catalog path baked into the locksmith Docker image.
/// Override via `LOCKSMITH_SEED_PATH` (set by tests; operators rarely
/// touch).
pub const DEFAULT_SEED_PATH: &str = "/etc/locksmith/seed/catalog.yaml";

#[derive(Debug, thiserror::Error)]
pub enum SeedLoadError {
    /// Catalog file IO error. NOT considered a startup-fatal error in
    /// production (the daemon logs and continues with an empty
    /// registrations table); see `load_or_skip` for the contract.
    #[error("io: {0}")]
    Io(String),
    /// Catalog file parse error. STARTUP-FATAL — the image ships a
    /// bad catalog.
    #[error("parse: {0}")]
    Parse(String),
    /// Per-entry validation failure. STARTUP-FATAL.
    #[error("entry {name:?} ({kind}): {error}")]
    Entry {
        name: String,
        kind: String,
        #[source]
        error: RegistrationError,
    },
    /// Repo write failure during seed apply.
    #[error("backend: {0}")]
    Backend(#[from] RegistrationError),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SeedCatalog {
    version: String,
    entries: Vec<SeedEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SeedEntry {
    name: String,
    kind: Kind,
    #[serde(default)]
    description: String,
    upstream: String,
    /// Required for kind=tool/model. Optional for kind=infra (defaults
    /// to AuthSpec::None when omitted).
    #[serde(default)]
    auth: Option<AuthSpec>,
    #[serde(default)]
    egress: Option<EgressMode>,
    #[serde(default)]
    timeouts: Option<ToolTimeouts>,
    #[serde(default)]
    body_limit_bytes: Option<u64>,
    #[serde(default)]
    metadata: Option<Json>,
}

/// Resolve the seed-catalog path from env override or default. Returns
/// `None` when `LOCKSMITH_SEED_PATH=""` is explicitly set (used in
/// tests that want to skip the seed loader entirely).
pub fn seed_path_from_env() -> Option<PathBuf> {
    match std::env::var("LOCKSMITH_SEED_PATH") {
        Ok(s) if s.is_empty() => None,
        Ok(s) => Some(PathBuf::from(s)),
        Err(_) => Some(PathBuf::from(DEFAULT_SEED_PATH)),
    }
}

/// Production entrypoint. Reads the catalog (if present), validates,
/// applies the diff. Missing-file is non-fatal (logged INFO);
/// parse/validation errors return Err so daemon.rs can decide whether
/// to ABORT startup.
pub async fn load_or_skip(repo: &RegistrationRepository, path: &Path) -> Result<(), SeedLoadError> {
    if !path.exists() {
        info!(
            path = %path.display(),
            "no seed catalog found; registrations table starts empty"
        );
        return Ok(());
    }
    let contents = std::fs::read_to_string(path)
        .map_err(|e| SeedLoadError::Io(format!("read {}: {e}", path.display())))?;
    apply_catalog(repo, &contents).await
}

/// Test-friendly variant — takes the catalog YAML as a string directly.
pub async fn apply_catalog(repo: &RegistrationRepository, yaml: &str) -> Result<(), SeedLoadError> {
    let catalog: SeedCatalog =
        serde_yaml::from_str(yaml).map_err(|e| SeedLoadError::Parse(format!("yaml: {e}")))?;
    apply_catalog_parsed(repo, catalog).await
}

async fn apply_catalog_parsed(
    repo: &RegistrationRepository,
    catalog: SeedCatalog,
) -> Result<(), SeedLoadError> {
    // Compare loaded version against DB. If equal, skip entirely.
    let current = repo.get_seed_version().await?;
    match current.as_deref() {
        Some(v) if v == catalog.version => {
            info!(
                version = %catalog.version,
                "seed catalog at current version; no changes"
            );
            return Ok(());
        }
        Some(v) if !semver_lt(v, &catalog.version) => {
            warn!(
                db_version = %v,
                catalog_version = %catalog.version,
                "seed catalog version is older than (or equal to) DB; skipping"
            );
            return Ok(());
        }
        _ => {}
    }

    // Validate every entry up-front. Catch malformed catalogs before
    // we touch the DB.
    for entry in &catalog.entries {
        validate_name(&entry.name).map_err(|e| SeedLoadError::Entry {
            name: entry.name.clone(),
            kind: entry.kind.to_string(),
            error: e,
        })?;
        check_auth_for_kind(entry).map_err(|e| SeedLoadError::Entry {
            name: entry.name.clone(),
            kind: entry.kind.to_string(),
            error: e,
        })?;
    }

    // Apply diff. We use upsert semantics that preserve operator
    // overrides (seed=0 rows): the loader skips them entirely. New
    // entries become seed=1; existing seed=1 entries get refreshed.
    let now = unix_now();
    let mut inserted = 0usize;
    let mut updated = 0usize;
    let mut skipped_overrides = 0usize;
    for entry in catalog.entries {
        let kind = entry.kind;
        match repo.get(&entry.name).await? {
            Some(existing) if !existing.seed => {
                // Operator override — never touch.
                skipped_overrides += 1;
                continue;
            }
            Some(existing) => {
                // Cross-kind change in catalog between versions is a
                // catalog bug; refuse to silently rewrite the row.
                if existing.kind != kind {
                    return Err(SeedLoadError::Entry {
                        name: entry.name.clone(),
                        kind: kind.to_string(),
                        error: RegistrationError::WrongKind {
                            existing_kind: existing.kind,
                            requested_kind: kind,
                        },
                    });
                }
                let mut next = entry_to_registration(entry, kind, now)?;
                // Preserve created_at + disabled across upgrades.
                next.created_at = existing.created_at;
                next.disabled = existing.disabled;
                repo.upsert(&next).await?;
                updated += 1;
            }
            None => {
                let r = entry_to_registration(entry, kind, now)?;
                repo.create(&r).await?;
                inserted += 1;
            }
        }
    }

    repo.set_seed_version(&catalog.version).await?;
    info!(
        version = %catalog.version,
        inserted,
        updated,
        skipped_overrides,
        "seed catalog applied"
    );
    Ok(())
}

fn check_auth_for_kind(entry: &SeedEntry) -> Result<(), RegistrationError> {
    // Field absent on kind=tool/kind=model is the footgun we close — the
    // operator must state intent (use `auth: { kind: none }` for authless).
    // Self-hosted/LAN-local models with `auth: none` are accepted on
    // kind=model (Ollama, LM Studio default-authless).
    match (entry.kind, &entry.auth) {
        (Kind::Tool, None) | (Kind::Model, None) => Err(RegistrationError::AuthRequired),
        _ => Ok(()),
    }
}

fn entry_to_registration(
    entry: SeedEntry,
    kind: Kind,
    now: i64,
) -> Result<Registration, SeedLoadError> {
    let auth = match (kind, entry.auth) {
        (Kind::Infra, None) => AuthSpec::None,
        (_, Some(a)) => a,
        // Unreachable — `check_auth_for_kind` already rejected None for
        // tool/model, but match exhaustiveness still requires a case.
        (Kind::Tool, None) | (Kind::Model, None) => {
            return Err(SeedLoadError::Entry {
                name: entry.name.clone(),
                kind: kind.to_string(),
                error: RegistrationError::AuthRequired,
            });
        }
    };
    Ok(Registration {
        name: entry.name,
        kind,
        description: entry.description,
        upstream: entry.upstream,
        auth,
        egress: entry.egress.unwrap_or_default(),
        timeouts: entry.timeouts.unwrap_or_default(),
        body_limit_bytes: entry.body_limit_bytes.unwrap_or(10 * 1024 * 1024),
        metadata: entry
            .metadata
            .unwrap_or_else(|| Json::Object(serde_json::Map::new())),
        seed: true,
        disabled: false,
        created_at: now,
        updated_at: now,
    })
}

/// Strict-less-than semver comparison. Returns true iff `a` < `b`.
/// Tolerates two-component (`major.minor`) versions for resilience.
fn semver_lt(a: &str, b: &str) -> bool {
    let parse = |s: &str| -> (u64, u64, u64) {
        let mut parts = s.split('.');
        let major = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
        let minor = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
        let patch = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
        (major, minor, patch)
    };
    parse(a) < parse(b)
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
