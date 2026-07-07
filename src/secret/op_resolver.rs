//! `op://` reference resolver — Phase J / M2 (CCS-8, WEM-443).
//!
//! The `op` custody backend ([`crate::registrations::AuthSpec::OpHeader`] /
//! `OpBearer`) stores only an `op://vault/item/field` reference. This
//! resolver materializes those references into secret values by shelling
//! out to the 1Password CLI (`op read <ref>`) **at startup and on catalog
//! change — never per request**. Results are held in an
//! [`arc_swap::ArcSwap`]-backed cache; the proxy hot path reads the cache
//! with a lock-free load and never invokes `op` (T2.3).
//!
//! **Degrade, never crash.** If `op` is missing or a read fails, the
//! affected reference is simply absent from the cache and an
//! operational-log warn is emitted (CCS-8) — the daemon keeps booting and
//! serving; an `op` registration whose value can't be resolved fails loud
//! at proxy time (503, T2.3) rather than forwarding unauthenticated.
//!
//! **Testable without `op`.** The resolution command is injected via the
//! [`OpCommand`] trait, so tests supply a fake resolver and never touch
//! the real CLI (which is absent in CI).

use crate::operational_log_sink::OperationalLogEmitter;
use arc_swap::ArcSwap;
use secrecy::SecretString;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::warn;

/// One-reference resolution command. Injected so tests can substitute a
/// fake for the real `op` CLI (which isn't installed in CI).
pub trait OpCommand: Send + Sync {
    /// Resolve a single `op://` reference to its secret value. `Err`
    /// (op missing, item not found, not signed in) degrades that one
    /// reference — it's omitted from the cache and logged.
    fn read(&self, reference: &str) -> Result<SecretString, String>;
}

/// Production [`OpCommand`] backed by the 1Password CLI: `op read <ref>`.
pub struct OpCliCommand;

impl OpCommand for OpCliCommand {
    fn read(&self, reference: &str) -> Result<SecretString, String> {
        let output = std::process::Command::new("op")
            .arg("read")
            .arg(reference)
            .output()
            .map_err(|e| format!("spawn op: {e}"))?;
        if !output.status.success() {
            return Err(format!("op read exited with status {}", output.status));
        }
        // `op read` emits the value + a trailing newline. Trim only the
        // trailing newline(s); interior whitespace is part of the value.
        let s = String::from_utf8_lossy(&output.stdout)
            .trim_end_matches(['\n', '\r'])
            .to_string();
        if s.is_empty() {
            return Err("op read returned empty value".to_string());
        }
        Ok(SecretString::from(s))
    }
}

/// Resolver + cache for `op://` references.
pub struct OpResolver {
    command: Box<dyn OpCommand>,
    cache: ArcSwap<HashMap<String, SecretString>>,
    emitter: Option<Arc<OperationalLogEmitter>>,
    /// Total `op` invocations since construction. Used by tests to prove
    /// the hot-path `get` never shells out (invocations happen only in
    /// `refresh`).
    invocations: AtomicU64,
}

impl OpResolver {
    /// Construct with an injected command (production wires
    /// [`OpResolver::with_cli`]; tests supply a fake).
    pub fn new(command: Box<dyn OpCommand>, emitter: Option<Arc<OperationalLogEmitter>>) -> Self {
        Self {
            command,
            cache: ArcSwap::from_pointee(HashMap::new()),
            emitter,
            invocations: AtomicU64::new(0),
        }
    }

    /// Construct the production resolver backed by the `op` CLI.
    pub fn with_cli(emitter: Option<Arc<OperationalLogEmitter>>) -> Self {
        Self::new(Box::new(OpCliCommand), emitter)
    }

    /// Resolve every reference in `references` and atomically swap the
    /// cache. Called at startup and on catalog change — NEVER on the hot
    /// path. Each reference that fails to resolve is omitted from the new
    /// cache and logged (degrade-not-crash, CCS-8). Duplicate references
    /// are resolved once.
    pub fn refresh(&self, references: &[String]) {
        let mut next: HashMap<String, SecretString> = HashMap::new();
        let mut degraded = 0usize;
        for reference in references {
            if next.contains_key(reference) {
                continue;
            }
            self.invocations.fetch_add(1, Ordering::Relaxed);
            match self.command.read(reference) {
                Ok(value) => {
                    next.insert(reference.clone(), value);
                }
                Err(e) => {
                    degraded += 1;
                    // Non-secret: the reference is a path (vault/item/field),
                    // not a value; the error is a CLI status, not a secret.
                    warn!(reference = %reference, error = %e, "op reference resolution failed; degraded");
                    if let Some(emitter) = self.emitter.as_ref() {
                        emitter.emit(
                            crate::repo::LogLevel::Warn,
                            crate::repo::LogComponent::Config,
                            "op_resolution_degraded",
                            "op:// reference could not be resolved; credential degraded",
                            Some(serde_json::json!({ "reference": reference, "error": e })),
                        );
                    }
                }
            }
        }
        let resolved = next.len();
        self.cache.store(Arc::new(next));
        if degraded > 0 {
            warn!(
                resolved,
                degraded, "op resolver refresh completed with degraded references"
            );
        }
    }

    /// Hot-path lookup (T2.3). Returns the cached value for `reference`,
    /// or `None` when it isn't resolved. NEVER invokes `op` — a lock-free
    /// cache load only.
    pub fn get(&self, reference: &str) -> Option<SecretString> {
        self.cache.load().get(reference).cloned()
    }

    /// Number of resolved references currently cached.
    pub fn cached_count(&self) -> usize {
        self.cache.load().len()
    }

    /// Total `op` invocations since construction. Test hook proving the
    /// hot path stays out of `op`.
    pub fn invocation_count(&self) -> u64 {
        self.invocations.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;
    use std::sync::Mutex;

    /// Fake command: serves values from a map, counts its own calls, and
    /// can be told to fail specific references.
    struct FakeOp {
        values: HashMap<String, String>,
        calls: Mutex<Vec<String>>,
    }

    impl FakeOp {
        fn new(pairs: &[(&str, &str)]) -> Self {
            Self {
                values: pairs
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
                calls: Mutex::new(Vec::new()),
            }
        }
    }

    impl OpCommand for FakeOp {
        fn read(&self, reference: &str) -> Result<SecretString, String> {
            self.calls.lock().unwrap().push(reference.to_string());
            match self.values.get(reference) {
                Some(v) => Ok(SecretString::from(v.clone())),
                None => Err("item not found".to_string()),
            }
        }
    }

    #[test]
    fn refresh_populates_cache_and_get_reads_it() {
        let fake = FakeOp::new(&[("op://v/item/field", "sk-op-secret")]);
        let resolver = OpResolver::new(Box::new(fake), None);
        resolver.refresh(&["op://v/item/field".to_string()]);
        assert_eq!(resolver.cached_count(), 1);
        let got = resolver.get("op://v/item/field").unwrap();
        assert_eq!(got.expose_secret(), "sk-op-secret");
    }

    #[test]
    fn missing_reference_degrades_without_crashing() {
        let fake = FakeOp::new(&[("op://v/item/good", "value")]);
        let resolver = OpResolver::new(Box::new(fake), None);
        resolver.refresh(&[
            "op://v/item/good".to_string(),
            "op://v/item/missing".to_string(),
        ]);
        // The good one resolved; the missing one is simply absent — no panic.
        assert_eq!(resolver.cached_count(), 1);
        assert!(resolver.get("op://v/item/good").is_some());
        assert!(resolver.get("op://v/item/missing").is_none());
    }

    #[test]
    fn get_never_invokes_op() {
        let fake = FakeOp::new(&[("op://v/item/field", "value")]);
        let resolver = OpResolver::new(Box::new(fake), None);
        resolver.refresh(&["op://v/item/field".to_string()]);
        let after_refresh = resolver.invocation_count();
        assert_eq!(after_refresh, 1, "one invocation during refresh");
        // Many hot-path lookups...
        for _ in 0..1000 {
            let _ = resolver.get("op://v/item/field");
            let _ = resolver.get("op://v/item/absent");
        }
        // ...invoke op zero additional times.
        assert_eq!(
            resolver.invocation_count(),
            after_refresh,
            "get must never shell out to op"
        );
    }

    #[test]
    fn refresh_resolves_duplicates_once() {
        let fake = FakeOp::new(&[("op://v/item/field", "value")]);
        let resolver = OpResolver::new(Box::new(fake), None);
        resolver.refresh(&[
            "op://v/item/field".to_string(),
            "op://v/item/field".to_string(),
        ]);
        assert_eq!(resolver.invocation_count(), 1, "duplicate resolved once");
        assert_eq!(resolver.cached_count(), 1);
    }

    #[test]
    fn refresh_replaces_prior_cache() {
        let resolver = OpResolver::new(
            Box::new(FakeOp::new(&[("op://v/a", "1"), ("op://v/b", "2")])),
            None,
        );
        resolver.refresh(&["op://v/a".to_string(), "op://v/b".to_string()]);
        assert_eq!(resolver.cached_count(), 2);
        // A second refresh with a narrower set drops the stale entry.
        resolver.refresh(&["op://v/a".to_string()]);
        assert_eq!(resolver.cached_count(), 1);
        assert!(resolver.get("op://v/b").is_none());
    }
}
