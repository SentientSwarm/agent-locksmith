//! Deprecation registry for configuration fields.
//!
//! INF-24: a single mechanism replaces per-field deprecation shims. The
//! registry holds an entry per deprecated/removed/renamed field. Each
//! entry's `notice()` returns `true` exactly once per process lifetime —
//! the second and subsequent occurrences are silenced — so hot reloads and
//! per-tool encounters do not flood the operator's logs.
//!
//! Initial registry entries (constructed via `default_registry()`):
//! - `tools[].cloud` → renamed to `tools[].egress` (M1, T1.6).
//! - `telemetry` → removed (was M0 dead code; OTel deferred per Q-19).
//! - `tools[].timeout_seconds` → renamed to `tools[].timeouts.request_seconds`
//!   (lands with T1.4).

use std::collections::HashSet;
use std::sync::Mutex;

/// What the loader should do when it encounters a registered field.
#[derive(Debug, Clone)]
pub enum DeprecationDisposition {
    /// The field was renamed; map to `new_name`. Loader-specific value
    /// translation (e.g. `cloud: true → egress: proxied`) is the loader's
    /// job; the registry only signals the shape change.
    Renamed { new_name: &'static str },
    /// The field is deprecated but still accepted with current semantics.
    Deprecated,
    /// The field is no longer interpreted; loader silently ignores it
    /// after emitting the one-shot warning.
    Removed,
}

#[derive(Debug, Clone)]
pub struct DeprecationEntry {
    /// Dotted path of the deprecated field. Indexed-collection elements
    /// use `[]` (e.g. `tools[].cloud`).
    pub field_path: &'static str,
    pub disposition: DeprecationDisposition,
    pub since_version: &'static str,
    pub removal_target: Option<&'static str>,
}

/// Registry of deprecated/removed/renamed config fields.
///
/// `notice(path)` returns `true` the first time `path` is seen and `false`
/// thereafter. Callers should emit a structured log message when `notice`
/// returns `true`. The state is per-instance; integration with the running
/// daemon uses a process-global registry constructed at startup.
pub struct DeprecationRegistry {
    entries: Vec<DeprecationEntry>,
    warned_once: Mutex<HashSet<String>>,
}

impl DeprecationRegistry {
    pub fn new(entries: Vec<DeprecationEntry>) -> Self {
        Self {
            entries,
            warned_once: Mutex::new(HashSet::new()),
        }
    }

    /// Look up the entry for `field_path`, if any.
    pub fn lookup(&self, field_path: &str) -> Option<&DeprecationEntry> {
        self.entries.iter().find(|e| e.field_path == field_path)
    }

    /// Record that the deprecated field was encountered. Returns `true` on
    /// the first call per (registry, field_path); `false` thereafter, and
    /// `false` for unknown fields.
    pub fn notice(&self, field_path: &str) -> bool {
        if self.lookup(field_path).is_none() {
            return false;
        }
        let mut warned = self
            .warned_once
            .lock()
            .expect("deprecation warned_once mutex poisoned");
        warned.insert(field_path.to_string())
    }

    /// All registered entries (for diagnostic listings).
    pub fn entries(&self) -> &[DeprecationEntry] {
        &self.entries
    }
}

/// The default registry shipped with the v2 binary. Wired into the config
/// loader by T1.6.
pub fn default_registry() -> DeprecationRegistry {
    DeprecationRegistry::new(vec![
        DeprecationEntry {
            field_path: "tools[].cloud",
            disposition: DeprecationDisposition::Renamed {
                new_name: "tools[].egress",
            },
            since_version: "0.2.0",
            removal_target: Some("0.3.0"),
        },
        DeprecationEntry {
            field_path: "telemetry",
            disposition: DeprecationDisposition::Removed,
            since_version: "0.2.0",
            removal_target: None,
        },
        DeprecationEntry {
            field_path: "tools[].timeout_seconds",
            disposition: DeprecationDisposition::Renamed {
                new_name: "tools[].timeouts.request_seconds",
            },
            since_version: "0.2.0",
            removal_target: Some("0.3.0"),
        },
        // M9 / v2.0.0 — `inbound_auth.token` is silently ignored when
        // the admin substrate is enabled (per-agent bearer authentication
        // takes over). Operators upgrading from M0/M1 must register
        // agents and use per-agent tokens.
        DeprecationEntry {
            field_path: "inbound_auth.token",
            disposition: DeprecationDisposition::Deprecated,
            since_version: "2.0.0",
            removal_target: None,
        },
    ])
}

/// Emit the M9 / v2.0.0 deprecation warning when `inbound_auth.token`
/// is set on a deployment that has the admin substrate enabled. The
/// shared bearer is silently ignored on the agent listener — per-agent
/// bearer authentication takes precedence — and operators should drop
/// the `inbound_auth` block to silence this warning. One-shot per
/// process via the registry's `notice()` mechanism.
pub fn emit_inbound_auth_token_runtime_deprecation(
    registry: &DeprecationRegistry,
    admin_substrate_enabled: bool,
    inbound_auth_token_set: bool,
) {
    if !(admin_substrate_enabled && inbound_auth_token_set) {
        return;
    }
    if !registry.notice("inbound_auth.token") {
        return;
    }
    let entry = match registry.lookup("inbound_auth.token") {
        Some(e) => e,
        None => return,
    };
    tracing::warn!(
        field = "inbound_auth.token",
        since_version = entry.since_version,
        "shared inbound_auth.token is ignored when the admin substrate is enabled — \
         per-agent bearer authentication takes precedence. Remove the inbound_auth block \
         to silence this warning. (M9 / v2.0.0)"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_registry_has_expected_entries() {
        let reg = default_registry();
        assert!(reg.lookup("tools[].cloud").is_some());
        assert!(reg.lookup("telemetry").is_some());
        assert!(reg.lookup("tools[].timeout_seconds").is_some());
    }
}
