//! Phase E (transitional) — migrate pre-Phase-E `config.tools` YAML
//! entries into the `registrations` table at daemon startup.
//!
//! Pre-Phase-E deployments stored their tool catalog in YAML loaded
//! into `AppConfig.tools`. Phase E moved the catalog to the
//! `registrations` table. To keep existing deployments running without
//! requiring a hand-edit, this shim runs at startup AFTER the seed
//! loader and BEFORE the daemon binds:
//!
//! - For each `config.tools` entry whose name isn't already in the
//!   registrations table: insert as `kind=tool`, `seed=false`
//!   (operator-authored).
//! - For each entry whose name IS already in the table (e.g., loaded
//!   by the seed catalog or previously written by admin PUT): skip.
//!   The DB row is the source of truth.
//!
//! Auth-shape translation:
//! - `auth: None` (no `auth:` block) → `AuthSpec::None`. Preserves
//!   pre-Phase-E "implicit absence means authless" semantics for
//!   tools migrated from existing site repos.
//! - `value: "${VAR}"` or `from_env { var }` with no prefix →
//!   `AuthSpec::Header { header, env_var: VAR }`.
//! - `value: "Bearer ${VAR}"` or `from_env { var, prefix: "Bearer " }`
//!   on the `Authorization` header → `AuthSpec::Bearer { env_var: VAR }`.
//!   Plain-string values are read as written, before `${VAR}` expansion
//!   (AGENT-299; see `ToolAuthConfig::written`).
//! - Any other prefix or text, and `from_file_sealed` / `from_vault` /
//!   `from_aws_secrets_manager` / `Inline`: SKIPPED with a WARN log per
//!   tool. A registration carries only a variable name.
//!
//! Deprecated. Removed in v0.3. By then operators are expected to have
//! either migrated to the seed catalog (E.7) or to the override-only
//! site-repo flow (E.8).

use crate::config::{AppConfig, ToolAuthConfig, WrittenValue};
use crate::registrations::{
    AuthSpec, Kind, Registration, RegistrationError, RegistrationRepository,
};
use crate::secret::SecretRef;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

/// Walk `cfg.tools` and migrate entries not already in the
/// registrations table. Returns a count of (inserted, skipped_existing,
/// skipped_unsupported_auth) for diagnostic logging.
pub async fn bootstrap_from_config_tools(
    repo: &RegistrationRepository,
    cfg: &AppConfig,
) -> Result<(usize, usize, usize), RegistrationError> {
    let mut inserted = 0;
    let mut skipped_existing = 0;
    let mut skipped_unsupported = 0;

    for tool in &cfg.tools {
        if repo.get(&tool.name).await?.is_some() {
            // Already in the table (seed loader or earlier admin PUT).
            // Don't clobber.
            skipped_existing += 1;
            continue;
        }

        let auth = match &tool.auth {
            None => AuthSpec::None,
            Some(ta) => match translate_auth(&tool.name, ta) {
                Some(spec) => spec,
                None => {
                    skipped_unsupported += 1;
                    continue;
                }
            },
        };

        let now = unix_now();
        let r = Registration {
            protocol: Default::default(),
            mcp: None,
            name: tool.name.clone(),
            kind: Kind::Tool,
            description: tool.description.clone(),
            upstream: tool.upstream.clone(),
            auth,
            egress: tool.egress,
            timeouts: tool.timeouts,
            body_limit_bytes: tool.body_limit_bytes,
            upstream_ca_pem: None,
            profile: None,
            broker: None,
            metadata: serde_json::Value::Object(serde_json::Map::new()),
            seed: false,
            disabled: false,
            created_at: now,
            updated_at: now,
        };
        repo.create(&r).await?;
        inserted += 1;
    }

    if inserted > 0 || skipped_unsupported > 0 {
        info!(
            inserted,
            skipped_existing,
            skipped_unsupported,
            "legacy bootstrap migrated config.tools entries into registrations"
        );
    }

    Ok((inserted, skipped_existing, skipped_unsupported))
}

/// Translate a pre-Phase-E `ToolAuthConfig` to an `AuthSpec`, or
/// `None` (with a warning naming the tool) for a shape no registration
/// can carry.
///
/// A registration keeps the variable name, so the value must be
/// recoverable from it:
/// - `${VAR}`, or `from_env` without a prefix → `Header`: the variable
///   holds the whole header value.
/// - `Bearer ${VAR}`, or `from_env` with prefix `Bearer `, on the
///   `Authorization` header → `Bearer`: the variable holds the token and
///   the proxy adds `Bearer `.
/// - Any other prefix or text, a `Bearer` prefix on another header,
///   sealed file, Vault, AWS or inline values are not migrated.
fn translate_auth(tool_name: &str, ta: &ToolAuthConfig) -> Option<AuthSpec> {
    let authorization = ta.header.eq_ignore_ascii_case("authorization");
    let header = |var: &str| AuthSpec::Header {
        header: ta.header.clone(),
        env_var: var.to_owned(),
    };
    let bearer = |var: &str| AuthSpec::Bearer {
        env_var: var.to_owned(),
    };
    let spec = match (&ta.value, &ta.written) {
        (SecretRef::FromEnv { var, prefix }, _) => match prefix.as_deref().unwrap_or("") {
            "" => Some(header(var)),
            "Bearer " if authorization => Some(bearer(var)),
            _ => None,
        },
        (SecretRef::LegacyString(_), Some(WrittenValue::Var(var))) => Some(header(var)),
        (SecretRef::LegacyString(_), Some(WrittenValue::BearerVar(var))) if authorization => {
            Some(bearer(var))
        }
        _ => None,
    };
    if spec.is_none() {
        warn!(
            tool = %tool_name,
            shape = %ta.value,
            "legacy bootstrap: unsupported auth shape; tool not migrated to registrations \
             (register it with the admin API, or write the value as `${{VAR}}` or `Bearer ${{VAR}}`)"
        );
    }
    spec
}

/// Extract a single `${VAR}` reference from a legacy-string value.
/// Returns `None` if the string contains zero or multiple `${...}`
/// references.
pub(crate) fn extract_single_env_var(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut i = 0;
    let mut found: Option<String> = None;
    while i + 1 < bytes.len() {
        if bytes[i] == b'$' && bytes[i + 1] == b'{' {
            let close = s[i + 2..].find('}')?;
            let name = &s[i + 2..i + 2 + close];
            if found.is_some() {
                return None; // Multiple references; refuse to guess.
            }
            found = Some(name.to_string());
            i += 2 + close + 1;
        } else {
            i += 1;
        }
    }
    found
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
#[path = "legacy_bootstrap_tests.rs"]
mod tests;
