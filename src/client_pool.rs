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

use crate::config::{AppConfig, EgressEnforcement, EgressMode, ToolConfig, ToolTimeouts};

/// AGENT-259 — why no client can serve a route. A proxied route never
/// gets a client that skips the proxy it was meant to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientUnavailable {
    /// The route is `proxied` but nothing enforces egress: no
    /// `egress_proxy` and no `egress.mode`.
    ProxyUnconfigured,
    /// The client (or its proxy) could not be built.
    BuildFailed,
}

/// Stable fingerprint of the tool fields that affect `Client` construction.
/// Two tool configs with the same fingerprint produce equivalent clients;
/// any change forces a rebuild.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ToolFingerprint {
    request_seconds: u64,
    idle_seconds: u64,
    egress: EgressMode,
    egress_proxy_url: Option<String>,
    enforcement: Option<EgressEnforcement>,
    /// #135 — SHA-256 of the route's own CA PEM; `None` uses the default
    /// trust (public roots plus the global bundle).
    upstream_ca_sha256: Option<String>,
}

impl ToolFingerprint {
    fn of(tool: &ToolConfig, config: &AppConfig) -> Self {
        Self::of_parts(tool.timeouts, tool.egress, None, config)
    }

    fn of_parts(
        timeouts: ToolTimeouts,
        egress: EgressMode,
        upstream_ca_pem: Option<&str>,
        config: &AppConfig,
    ) -> Self {
        Self {
            request_seconds: timeouts.request_seconds,
            idle_seconds: timeouts.idle_seconds,
            egress,
            // Egress proxy is shared across tools but only matters when
            // the tool is `proxied`. Including it in the fingerprint means
            // changes to the global proxy URL evict every proxied tool's
            // client (which is the right behavior).
            egress_proxy_url: if matches!(egress, EgressMode::Proxied) {
                config.egress_proxy.clone()
            } else {
                None
            },
            enforcement: config.egress_enforcement(),
            upstream_ca_sha256: upstream_ca_pem.map(crate::registrations::upstream_ca::sha256_hex),
        }
    }
}

/// Every client in the pool refuses to follow redirects (#159,
/// AGENT-242). A followed cross-host redirect would carry Locksmith's
/// injected key to a host the route never named: reqwest strips
/// `Authorization` and cookies on such hops but keeps custom names such
/// as `x-api-key`. The 3xx goes back to the agent instead, with a
/// same-upstream `Location` already rewritten onto the route.
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
    pub fn get_or_build(
        &self,
        tool: &ToolConfig,
        config: &AppConfig,
    ) -> Result<Arc<Client>, ClientUnavailable> {
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
                return Ok(Arc::clone(client));
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
            return Ok(Arc::clone(client));
        }
        let client = Arc::new(build_client(tool, config)?);
        entries.insert(tool.name.clone(), (Arc::clone(&client), fingerprint));
        Ok(client)
    }

    /// Phase E.6 — variant keyed by fields rather than a `ToolConfig`.
    /// Used by the proxy hot path when the target came from the
    /// registrations catalog (no `ToolConfig` available). Same caching
    /// semantics, same fingerprint shape, so registration-sourced and
    /// config-sourced clients share the cache by name when they share
    /// timeouts and egress.
    pub fn get_or_build_for(
        &self,
        name: &str,
        timeouts: ToolTimeouts,
        egress: EgressMode,
        upstream_ca_pem: Option<&str>,
        config: &AppConfig,
    ) -> Result<Arc<Client>, ClientUnavailable> {
        let fingerprint = ToolFingerprint::of_parts(timeouts, egress, upstream_ca_pem, config);

        {
            let entries = self
                .entries
                .read()
                .expect("client_pool entries lock poisoned");
            if let Some((client, cached_fp)) = entries.get(name)
                && cached_fp == &fingerprint
            {
                return Ok(Arc::clone(client));
            }
        }

        let mut entries = self
            .entries
            .write()
            .expect("client_pool entries lock poisoned");
        if let Some((client, cached_fp)) = entries.get(name)
            && cached_fp == &fingerprint
        {
            return Ok(Arc::clone(client));
        }
        let client = Arc::new(build_client_for(timeouts, egress, upstream_ca_pem, config)?);
        entries.insert(name.to_string(), (Arc::clone(&client), fingerprint));
        Ok(client)
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

fn build_client(tool: &ToolConfig, config: &AppConfig) -> Result<Client, ClientUnavailable> {
    build_client_for(tool.timeouts, tool.egress, None, config)
}

fn build_client_for(
    timeouts: ToolTimeouts,
    egress: EgressMode,
    upstream_ca_pem: Option<&str>,
    config: &AppConfig,
) -> Result<Client, ClientUnavailable> {
    let proxy = egress_proxy(egress, config)?;
    let mut builder = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(timeouts.request_seconds))
        .read_timeout(Duration::from_secs(timeouts.idle_seconds));
    // AGENT-259 — the route's proxy or none at all: reqwest would otherwise
    // pick up HTTP(S)_PROXY / ALL_PROXY from the daemon's environment and
    // send direct and `external` traffic to a proxy no route names.
    builder = match proxy.clone() {
        Some(proxy) => builder.proxy(proxy),
        None => builder.no_proxy(),
    };

    if let Some(pem) = upstream_ca_pem {
        // #135 — the route's own anchors replace every other root. Fail
        // closed: an unusable stored value leaves no anchors, so TLS fails.
        builder = route_only_trust(builder, pem);
        return finish(builder, proxy.is_some(), no_trust_client);
    }

    // Extra upstream-CA trust (e.g. an internal CA in front of an HTTPS
    // upstream). reqwest's rustls+webpki roots ignore the system store,
    // so private CAs must be named explicitly; this only ADDS roots.
    if let Some(tls) = &config.tls
        && let Some(ca_path) = &tls.upstream_ca_bundle
    {
        builder = add_ca_bundle(builder, ca_path);
    }
    finish(builder, proxy.is_some(), no_redirect_client)
}

/// AGENT-259 — the proxy a route must use. `proxied` routes get the
/// configured proxy under `pipelock`, none under `external`, and an error
/// when nothing enforces egress: they never fall through to direct.
fn egress_proxy(
    egress: EgressMode,
    config: &AppConfig,
) -> Result<Option<reqwest::Proxy>, ClientUnavailable> {
    if !matches!(egress, EgressMode::Proxied) {
        return Ok(None);
    }
    match config.egress_enforcement() {
        None => Err(ClientUnavailable::ProxyUnconfigured),
        Some(EgressEnforcement::External) => Ok(None),
        Some(EgressEnforcement::Pipelock) => {
            let url = config
                .egress_proxy
                .as_deref()
                .ok_or(ClientUnavailable::ProxyUnconfigured)?;
            reqwest::Proxy::all(url)
                .map(Some)
                .map_err(|_| ClientUnavailable::BuildFailed)
        }
    }
}

/// Build the client. A failed build for a proxied route is an error:
/// the fallbacks below carry no proxy. Direct routes keep a fallback that
/// still refuses redirects (and, for route-CA routes, trusts nothing).
fn finish(
    builder: reqwest::ClientBuilder,
    proxied: bool,
    fallback: fn() -> Client,
) -> Result<Client, ClientUnavailable> {
    match builder.build() {
        Ok(client) => Ok(client),
        Err(_) if proxied => Err(ClientUnavailable::BuildFailed),
        Err(_) => Ok(fallback()),
    }
}

/// AGENT-277 — a builder for clients outside the route pool (OAuth, CRL).
/// It never reads `HTTP(S)_PROXY` / `ALL_PROXY`, which reqwest otherwise
/// honours: token and CRL fetches must not reach a proxy nothing names.
pub fn unproxied() -> reqwest::ClientBuilder {
    Client::builder().no_proxy()
}

/// The fallback when an [`unproxied`] build fails; still no env proxy.
pub fn unproxied_default() -> Client {
    unproxied().build().expect("a default client always builds")
}

/// Last resort when a configured client cannot be built. It still never
/// follows redirects, like every other client in the pool.
fn no_redirect_client() -> Client {
    Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .expect("a default client always builds")
}

/// #135 — trust only `pem`'s certificates. Each becomes a trust anchor, so
/// an intermediate alone suffices (partial chain).
fn route_only_trust(builder: reqwest::ClientBuilder, pem: &str) -> reqwest::ClientBuilder {
    let mut builder = builder.tls_built_in_root_certs(false);
    let certs = crate::registrations::upstream_ca::der_certificates(pem).map(|ders| {
        ders.iter()
            .map(|der| reqwest::Certificate::from_der(der))
            .collect::<Result<Vec<_>, _>>()
    });
    match certs {
        Some(Ok(certs)) => {
            for cert in certs {
                builder = builder.add_root_certificate(cert);
            }
        }
        _ => tracing::warn!("route upstream CA unusable; route has no trust anchors"),
    }
    builder
}

/// Last resort when a route-CA client cannot be built: no roots, so every
/// TLS handshake fails rather than falling back to public trust.
fn no_trust_client() -> Client {
    Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .tls_built_in_root_certs(false)
        .build()
        .expect("a client without roots always builds")
}

/// Add each PEM certificate in `ca_path` to the client's root store.
/// Failures degrade to built-in-roots-only with a warning (never a hard
/// error and never accept-invalid-certs — a missing CA file must not
/// silently disable verification).
pub(crate) fn add_ca_bundle(
    mut builder: reqwest::ClientBuilder,
    ca_path: &std::path::Path,
) -> reqwest::ClientBuilder {
    let pem = match std::fs::read(ca_path) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(
                path = %ca_path.display(), error = %e,
                "tls.upstream_ca_bundle unreadable; using built-in roots only",
            );
            return builder;
        }
    };
    let mut added = 0usize;
    for block in split_pem_certificates(&pem) {
        match reqwest::Certificate::from_pem(&block) {
            Ok(cert) => {
                builder = builder.add_root_certificate(cert);
                added += 1;
            }
            Err(e) => tracing::warn!(error = %e, "skipping malformed cert in upstream_ca_bundle"),
        }
    }
    if added == 0 {
        tracing::warn!(path = %ca_path.display(), "no usable certs in upstream_ca_bundle");
    } else {
        tracing::info!(path = %ca_path.display(), count = added, "added upstream CA root(s)");
    }
    builder
}

/// Split a PEM file into individual `BEGIN/END CERTIFICATE` blocks so each
/// can be handed to `reqwest::Certificate::from_pem` (which takes one cert).
fn split_pem_certificates(pem: &[u8]) -> Vec<Vec<u8>> {
    let text = String::from_utf8_lossy(pem);
    let mut certs = Vec::new();
    let mut current = String::new();
    let mut in_cert = false;
    for line in text.lines() {
        if line.contains("BEGIN CERTIFICATE") {
            in_cert = true;
            current.clear();
        }
        if in_cert {
            current.push_str(line);
            current.push('\n');
        }
        if line.contains("END CERTIFICATE") {
            in_cert = false;
            certs.push(current.as_bytes().to_vec());
        }
    }
    certs
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_proxied_client_that_fails_to_build_is_unavailable() {
        // AGENT-269: no fallback for a proxied route, since the fallback
        // carries no proxy. A minimum TLS version above the maximum can't
        // build.
        let broken = || {
            Client::builder()
                .min_tls_version(reqwest::tls::Version::TLS_1_3)
                .max_tls_version(reqwest::tls::Version::TLS_1_2)
        };
        assert!(broken().build().is_err(), "the builder must fail");
        assert!(matches!(
            finish(broken(), true, no_redirect_client),
            Err(ClientUnavailable::BuildFailed)
        ));
        assert!(finish(broken(), false, no_redirect_client).is_ok());
    }

    use super::*;

    /// AGENT-277 — every reqwest client the daemon builds ignores proxy
    /// environment variables. reqwest reads them unless a client is given
    /// a proxy or `.no_proxy()`, so each `Client::builder()` in `src/` must
    /// say `.no_proxy()` (or come from [`unproxied`]) and nothing may use
    /// `Client::new()`. The operator CLI runs in the operator's own shell
    /// and is exempt; test fixtures are too.
    #[test]
    fn no_daemon_client_reads_the_proxy_environment() {
        fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    walk(&path, out);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    out.push(path);
                }
            }
        }
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        walk(&root, &mut files);
        let mut offenders = Vec::new();
        for file in files {
            let rel = file
                .strip_prefix(&root)
                .unwrap()
                .to_string_lossy()
                .into_owned();
            if rel == "client_pool.rs" || rel.starts_with("cli/") || rel.ends_with("fixture.rs") {
                continue;
            }
            let text = std::fs::read_to_string(&file).unwrap();
            let lines: Vec<&str> = text.lines().collect();
            for (i, line) in lines.iter().enumerate() {
                if line.contains("Client::new()") {
                    offenders.push(format!("{rel}:{}", i + 1));
                }
                if line.contains("Client::builder()") {
                    let window = lines[i..(i + 3).min(lines.len())].concat();
                    if !window.contains(".no_proxy()") {
                        offenders.push(format!("{rel}:{}", i + 1));
                    }
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "clients that read the proxy env: {offenders:?}"
        );
    }
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
            response: None,
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
    fn proxied_tool_without_enforcement_gets_no_client() {
        let pool = ClientPool::new();
        let mut t = tool("out", 30);
        t.egress = EgressMode::Proxied;
        assert_eq!(
            pool.get_or_build(&t, &empty_config()).err(),
            Some(ClientUnavailable::ProxyUnconfigured)
        );
        assert_eq!(pool.len(), 0, "a refusal is never cached");
    }

    #[test]
    fn returns_same_arc_for_unchanged_tool() {
        let pool = ClientPool::new();
        let cfg = empty_config();
        let t = tool("github", 30);
        let a = pool.get_or_build(&t, &cfg).unwrap();
        let b = pool.get_or_build(&t, &cfg).unwrap();
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
        let a = pool.get_or_build(&tool("github", 30), &cfg).unwrap();
        let b = pool.get_or_build(&tool("github", 60), &cfg).unwrap();
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
        let github = pool.get_or_build(&tool("github", 30), &cfg).unwrap();
        let anthropic = pool.get_or_build(&tool("anthropic", 30), &cfg).unwrap();
        assert!(!Arc::ptr_eq(&github, &anthropic));
        assert_eq!(pool.len(), 2);
    }

    #[test]
    fn cleanup_removed_drops_unlisted_entries() {
        let pool = ClientPool::new();
        let cfg = empty_config();
        let _g = pool.get_or_build(&tool("github", 30), &cfg).unwrap();
        let _a = pool.get_or_build(&tool("anthropic", 30), &cfg).unwrap();
        assert_eq!(pool.len(), 2);
        pool.cleanup_removed(&["anthropic"]);
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn split_pem_certificates_handles_bundle_and_junk() {
        // Two cert blocks separated by junk + leading/trailing noise.
        let pem = b"# comment\n\
            -----BEGIN CERTIFICATE-----\nAAAA\nBBBB\n-----END CERTIFICATE-----\n\
            some junk between\n\
            -----BEGIN CERTIFICATE-----\nCCCC\n-----END CERTIFICATE-----\ntrailing\n";
        let blocks = split_pem_certificates(pem);
        assert_eq!(blocks.len(), 2, "two cert blocks");
        let first = String::from_utf8_lossy(&blocks[0]);
        assert!(first.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(first.trim_end().ends_with("-----END CERTIFICATE-----"));
        assert!(first.contains("AAAA") && first.contains("BBBB"));
        assert!(!first.contains("junk"));
        assert!(String::from_utf8_lossy(&blocks[1]).contains("CCCC"));
    }

    #[test]
    fn split_pem_certificates_empty_on_no_certs() {
        assert!(split_pem_certificates(b"no certs here\n").is_empty());
    }

    #[test]
    fn unreadable_ca_bundle_degrades_to_builtin_roots() {
        // A missing CA file must NOT hard-fail or disable verification —
        // build still yields a usable client (built-in roots only).
        let builder = add_ca_bundle(
            Client::builder(),
            std::path::Path::new("/nonexistent/ca.pem"),
        );
        assert!(builder.build().is_ok());
    }
}
