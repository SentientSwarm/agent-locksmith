//! `op://` reference resolver — Phase J / M2 (CCS-8, WEM-443).
//!
//! The `op` custody backend ([`crate::registrations::AuthSpec::OpHeader`] /
//! `OpBearer`) stores only an `op://vault/item/field` reference. This
//! resolver materializes those references into secret values by shelling
//! out to the 1Password CLI (`op read <ref>`) **at startup and on catalog
//! or per-agent-override change — never per request**. Results are held in an
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
use crate::registrations::{Catalog, Kind};
use crate::repo::AgentCredentialRepository;
use arc_swap::ArcSwap;
use secrecy::SecretString;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
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
    /// `refresh` / `sync`).
    invocations: AtomicU64,
    /// Serializes cache swaps (`refresh` / `sync`).
    rebuild: Mutex<()>,
    /// Held by [`resync_op_references`] across the whole collect → resolve
    /// → publish cycle, so a resync that snapshotted older state can never
    /// publish after (and evict references added by) a newer one.
    resync: tokio::sync::Mutex<()>,
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
            rebuild: Mutex::new(()),
            resync: tokio::sync::Mutex::new(()),
        }
    }

    /// Construct the production resolver backed by the `op` CLI.
    pub fn with_cli(emitter: Option<Arc<OperationalLogEmitter>>) -> Self {
        Self::new(Box::new(OpCliCommand), emitter)
    }

    /// Resolve every reference in `references` and atomically swap the
    /// cache. NEVER on the hot path. Each reference that fails to resolve
    /// is omitted from the new cache and logged (degrade-not-crash, CCS-8).
    /// Duplicate references are attempted once, whether or not they
    /// resolve.
    pub fn refresh(&self, references: &[String]) {
        self.rebuild(references, false);
    }

    /// Incrementally reconcile the cache with `references` on catalog or
    /// per-agent-override change (T2.2 "on-change"). Values already cached
    /// for a still-referenced key are kept without re-invoking `op`; keys
    /// not yet cached — new references, or ones that degraded earlier —
    /// are resolved; keys no longer referenced are dropped. NEVER on the
    /// hot path.
    pub fn sync(&self, references: &[String]) {
        self.rebuild(references, true);
    }

    fn rebuild(&self, references: &[String], reuse_cached: bool) {
        let _guard = self.rebuild.lock().unwrap_or_else(|e| e.into_inner());
        let current = self.cache.load();
        let mut next: HashMap<String, SecretString> = HashMap::new();
        let mut seen: HashSet<&str> = HashSet::new();
        let mut degraded = 0usize;
        for reference in references {
            if !seen.insert(reference.as_str()) {
                continue;
            }
            if reuse_cached && let Some(value) = current.get(reference) {
                next.insert(reference.clone(), value.clone());
                continue;
            }
            match self.resolve_one(reference) {
                Some(value) => {
                    next.insert(reference.clone(), value);
                }
                None => degraded += 1,
            }
        }
        let resolved = next.len();
        self.cache.store(Arc::new(next));
        if degraded > 0 {
            warn!(
                resolved,
                degraded, "op resolver rebuild completed with degraded references"
            );
        }
    }

    /// Invoke `op` for one reference. `None` (logged + emitted on the
    /// operational-log stream) when it can't be resolved.
    fn resolve_one(&self, reference: &str) -> Option<SecretString> {
        self.invocations.fetch_add(1, Ordering::Relaxed);
        match self.command.read(reference) {
            Ok(value) => Some(value),
            Err(e) => {
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
                None
            }
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

/// Every `op://` reference in use by an enabled registration in
/// `catalog`, de-duplicated, in catalog order. References only — never a
/// value (CCS-8).
pub fn catalog_op_references(catalog: &Catalog) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for kind in [Kind::Tool, Kind::Model, Kind::Infra] {
        for r in catalog.iter_enabled_by_kind(kind) {
            if let Some(reference) = r.auth.op_reference()
                && seen.insert(reference.to_string())
            {
                out.push(reference.to_string());
            }
        }
    }
    out
}

/// Reconcile `resolver` with every `op://` reference currently in use:
/// enabled registrations in the current catalog plus every per-agent
/// override. Called at startup, after each catalog refresh, and after each
/// override mutation, so an `op` credential added at runtime — or
/// referenced only by an override — resolves without a restart (T2.2).
///
/// The whole cycle runs under the resolver's resync lock and reads the
/// catalog from `catalog` *inside* it, so concurrent admin writes publish
/// in order: the last resync to run always saw the newest state. The `op`
/// reads run on the blocking pool. If the override table can't be read,
/// the cache is left untouched rather than shrunk to a partial set.
pub async fn resync_op_references(
    resolver: &Arc<OpResolver>,
    catalog: &ArcSwap<Catalog>,
    overrides: Option<&AgentCredentialRepository>,
) {
    let _cycle = resolver.resync.lock().await;
    let mut references = catalog_op_references(&catalog.load());
    if let Some(repo) = overrides {
        match repo.list_all().await {
            Ok(rows) => references.extend(
                rows.iter()
                    .filter_map(|o| o.auth_spec.op_reference().map(str::to_string)),
            ),
            Err(e) => {
                warn!(error = %e, "op resync skipped: agent override read failed; cache unchanged");
                return;
            }
        }
    }
    let resolver = resolver.clone();
    if let Err(e) = tokio::task::spawn_blocking(move || resolver.sync(&references)).await {
        warn!(error = %e, "op resync task failed; cache unchanged");
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

    #[test]
    fn sync_keeps_cached_values_without_reinvoking_op() {
        let resolver = OpResolver::new(
            Box::new(FakeOp::new(&[("op://v/a", "1"), ("op://v/b", "2")])),
            None,
        );
        resolver.sync(&["op://v/a".to_string()]);
        assert_eq!(resolver.invocation_count(), 1);
        // Adding a reference resolves only the new one.
        resolver.sync(&["op://v/a".to_string(), "op://v/b".to_string()]);
        assert_eq!(resolver.invocation_count(), 2, "cached `a` not re-read");
        assert_eq!(resolver.get("op://v/a").unwrap().expose_secret(), "1");
        assert_eq!(resolver.get("op://v/b").unwrap().expose_secret(), "2");
    }

    #[test]
    fn sync_drops_unreferenced_values() {
        let resolver = OpResolver::new(
            Box::new(FakeOp::new(&[("op://v/a", "1"), ("op://v/b", "2")])),
            None,
        );
        resolver.sync(&["op://v/a".to_string(), "op://v/b".to_string()]);
        resolver.sync(&["op://v/b".to_string()]);
        assert!(
            resolver.get("op://v/a").is_none(),
            "dropped reference evicted"
        );
        assert!(resolver.get("op://v/b").is_some());
        assert_eq!(resolver.invocation_count(), 2, "no re-read on shrink");
    }

    #[test]
    fn sync_retries_previously_degraded_reference() {
        let resolver = OpResolver::new(Box::new(FakeOp::new(&[])), None);
        resolver.sync(&["op://v/missing".to_string()]);
        resolver.sync(&["op://v/missing".to_string()]);
        assert_eq!(
            resolver.invocation_count(),
            2,
            "a degraded reference is retried on the next sync"
        );
        assert_eq!(resolver.cached_count(), 0);
    }

    #[test]
    fn sync_resolves_duplicates_once() {
        let resolver = OpResolver::new(Box::new(FakeOp::new(&[("op://v/a", "1")])), None);
        resolver.sync(&["op://v/a".to_string(), "op://v/a".to_string()]);
        assert_eq!(resolver.invocation_count(), 1);
        assert_eq!(resolver.cached_count(), 1);
    }

    #[test]
    fn failing_duplicate_reference_is_attempted_once() {
        let resolver = OpResolver::new(Box::new(FakeOp::new(&[])), None);
        resolver.sync(&[
            "op://v/missing".to_string(),
            "op://v/missing".to_string(),
            "op://v/missing".to_string(),
        ]);
        assert_eq!(
            resolver.invocation_count(),
            1,
            "a reference shared by several overrides is tried once per sync"
        );
    }
}
