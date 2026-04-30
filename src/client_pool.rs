//! Per-tool reqwest client pool (T1.3 / INF-25 / Q-27).
//!
//! M0 built a fresh `reqwest::Client` per request, which defeats keep-alive
//! and TLS session reuse. The pool caches one `Arc<Client>` per tool name
//! and rebuilds only when the tool's client-affecting fields change
//! (timeouts, egress, etc.) — detected via a fingerprint stored alongside
//! the cached client.
//!
//! Hot reload of the YAML config (M2 / T2.20) doesn't yet exist; once it
//! does, the pool naturally tracks config changes through fingerprint
//! comparison on each lookup, and `cleanup_removed` purges entries for
//! tools that no longer appear in the active config.

use reqwest::Client;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use crate::config::{AppConfig, EgressMode, ToolConfig};

/// Stable fingerprint of the tool fields that affect `Client` construction.
/// Two tool configs with the same fingerprint produce equivalent clients;
/// any change forces a rebuild.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ToolFingerprint {
    request_seconds: u64,
    idle_seconds: u64,
    egress: EgressMode,
    egress_proxy_url: Option<String>,
}

impl ToolFingerprint {
    fn of(tool: &ToolConfig, config: &AppConfig) -> Self {
        Self {
            request_seconds: tool.timeouts.request_seconds,
            idle_seconds: tool.timeouts.idle_seconds,
            egress: tool.egress,
            // Egress proxy is shared across tools but only matters when
            // the tool is `proxied`. Including it in the fingerprint means
            // changes to the global proxy URL evict every proxied tool's
            // client (which is the right behavior).
            egress_proxy_url: if matches!(tool.egress, EgressMode::Proxied) {
                config.egress_proxy.clone()
            } else {
                None
            },
        }
    }
}

#[derive(Default)]
pub struct ClientPool {
    entries: RwLock<HashMap<String, (Arc<Client>, ToolFingerprint)>>,
}

impl ClientPool {
    pub fn new() -> Self {
        Self::default()
    }

    /// Get an `Arc<Client>` for `tool`, building (or rebuilding) only if no
    /// cached client matches the tool's current fingerprint.
    pub fn get_or_build(&self, tool: &ToolConfig, config: &AppConfig) -> Arc<Client> {
        let fingerprint = ToolFingerprint::of(tool, config);

        // Fast path: matching cached entry.
        {
            let entries = self
                .entries
                .read()
                .expect("client_pool entries lock poisoned");
            if let Some((client, cached_fp)) = entries.get(&tool.name)
                && cached_fp == &fingerprint
            {
                return Arc::clone(client);
            }
        }

        // Slow path: build a new client and insert. Re-check under the
        // write lock in case another caller raced us to build the same
        // tool's client; a redundant build is fine but redundant insert
        // would replace a possibly-valid entry — checking handles that.
        let mut entries = self
            .entries
            .write()
            .expect("client_pool entries lock poisoned");
        if let Some((client, cached_fp)) = entries.get(&tool.name)
            && cached_fp == &fingerprint
        {
            return Arc::clone(client);
        }
        let client = Arc::new(build_client(tool, config));
        entries.insert(tool.name.clone(), (Arc::clone(&client), fingerprint));
        client
    }

    /// Remove cache entries for tool names not in `keep`. Called by M2's
    /// hot-reload mechanism after a successful config swap to drop clients
    /// whose tool was removed from configuration.
    pub fn cleanup_removed(&self, keep: &[&str]) {
        let mut entries = self
            .entries
            .write()
            .expect("client_pool entries lock poisoned");
        entries.retain(|name, _| keep.iter().any(|k| *k == name));
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries
            .read()
            .expect("client_pool entries lock poisoned")
            .len()
    }
}

fn build_client(tool: &ToolConfig, config: &AppConfig) -> Client {
    let mut builder = Client::builder()
        .timeout(Duration::from_secs(tool.timeouts.request_seconds))
        .read_timeout(Duration::from_secs(tool.timeouts.idle_seconds));

    if matches!(tool.egress, EgressMode::Proxied)
        && let Some(proxy_url) = &config.egress_proxy
        && let Ok(proxy) = reqwest::Proxy::all(proxy_url)
    {
        builder = builder.proxy(proxy);
    }

    builder.build().unwrap_or_else(|_| Client::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ToolConfig, ToolTimeouts};

    fn tool(name: &str, request_seconds: u64) -> ToolConfig {
        ToolConfig {
            name: name.to_string(),
            description: String::new(),
            upstream: "http://x".to_string(),
            egress: EgressMode::Direct,
            auth: None,
            timeouts: ToolTimeouts {
                request_seconds,
                idle_seconds: 60,
            },
            body_limit_bytes: 1024,
        }
    }

    fn empty_config() -> AppConfig {
        crate::config::parse_config_str(
            r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools: []
"#,
        )
        .unwrap()
    }

    #[test]
    fn returns_same_arc_for_unchanged_tool() {
        let pool = ClientPool::new();
        let cfg = empty_config();
        let t = tool("github", 30);
        let a = pool.get_or_build(&t, &cfg);
        let b = pool.get_or_build(&t, &cfg);
        assert!(
            Arc::ptr_eq(&a, &b),
            "second lookup should return the cached Arc"
        );
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn rebuilds_when_fingerprint_changes() {
        let pool = ClientPool::new();
        let cfg = empty_config();
        let a = pool.get_or_build(&tool("github", 30), &cfg);
        let b = pool.get_or_build(&tool("github", 60), &cfg);
        assert!(
            !Arc::ptr_eq(&a, &b),
            "different fingerprint must produce a new client"
        );
        assert_eq!(pool.len(), 1, "still one entry; old replaced");
    }

    #[test]
    fn independent_entries_per_tool() {
        let pool = ClientPool::new();
        let cfg = empty_config();
        let github = pool.get_or_build(&tool("github", 30), &cfg);
        let anthropic = pool.get_or_build(&tool("anthropic", 30), &cfg);
        assert!(!Arc::ptr_eq(&github, &anthropic));
        assert_eq!(pool.len(), 2);
    }

    #[test]
    fn cleanup_removed_drops_unlisted_entries() {
        let pool = ClientPool::new();
        let cfg = empty_config();
        let _g = pool.get_or_build(&tool("github", 30), &cfg);
        let _a = pool.get_or_build(&tool("anthropic", 30), &cfg);
        assert_eq!(pool.len(), 2);
        pool.cleanup_removed(&["anthropic"]);
        assert_eq!(pool.len(), 1);
    }
}
