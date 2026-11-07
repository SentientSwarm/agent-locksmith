//! T6.3/T6.4 — revocation sources for the running agent listener.
//!
//! Builds the CRL store and the local emergency blocklist named by
//! `listen.mtls`, attaches them to the validator, and keeps them fresh.
//! Only CRLs signed by the agent CA bundle are applied (see
//! `CrlStore::trusting`).
//!
//! CRL: before the listener serves, the last good CRL is reloaded from
//! `cache_path` (each issuer's block is re-verified; one past `nextUpdate`
//! still applies, with a warning, since it only adds denials) and then
//! the CRL is fetched once. Every successfully applied
//! CRL is written back to the cache, so a restart while the CA is
//! unreachable keeps the revocations already known. A failed fetch keeps
//! the previous snapshot and is retried after at most `CRL_RETRY` instead
//! of a full `crl_refresh_interval_seconds`. Until some CRL has been
//! applied, the validator refuses every mTLS client (fail closed). The
//! fetch trusts the built-in roots plus the agent CA bundle and
//! `tls.upstream_ca_bundle`.
//!
//! Blocklist: re-read every `blocklist_reload_interval_seconds` when its
//! modification time or length changes.

use super::{Blocklist, CrlStore, MtlsValidator, blocklist::write_atomic, crl};
use crate::config::MtlsConfig;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, warn};

/// Retry delay after a failed CRL fetch (capped by the refresh interval).
const CRL_RETRY: Duration = Duration::from_secs(30);

struct CrlSource {
    store: Arc<CrlStore>,
    url: String,
    period: Duration,
    client: reqwest::Client,
    cache_path: PathBuf,
}

impl CrlSource {
    async fn refresh(&self) -> bool {
        let ok = crl::refresh_once(&self.store, &self.client, &self.url).await;
        if ok
            && let Some(pem) = self.store.to_pem()
            && let Err(e) = write_atomic(&self.cache_path, pem.as_bytes())
        {
            warn!(path = %self.cache_path.display(), error = %e, "CRL cache write failed");
        }
        ok
    }

    fn load_cache(&self) {
        let Ok(body) = std::fs::read(&self.cache_path) else {
            return;
        };
        let n = self.store.apply_cached(&body);
        if self.store.in_force() {
            info!(path = %self.cache_path.display(), revoked_count = n, "last good CRL reloaded");
        } else {
            warn!(path = %self.cache_path.display(), "no usable CRL in the cache");
        }
    }
}

pub struct Revocation {
    blocklist: Option<(Arc<Blocklist>, Duration)>,
    crl: Option<CrlSource>,
    crl_ok: bool,
}

impl Revocation {
    /// Load every configured source. Reloads the cached CRL and performs
    /// the initial fetch. `ca_bundle_pem` is the agent CA bundle, which
    /// also signs CRLs; `fetch_roots` are extra TLS roots for the fetch;
    /// `cache_path` holds the last good CRL.
    pub async fn load(
        cfg: &MtlsConfig,
        ca_bundle_pem: &str,
        fetch_roots: &[PathBuf],
        cache_path: &Path,
    ) -> Result<Self, String> {
        let blocklist = cfg.blocklist_path.as_ref().map(|path| {
            let list = Arc::new(Blocklist::open(path));
            info!(path = %path.display(), serials = list.len(), "mtls blocklist loaded");
            (list, interval(cfg.blocklist_reload_interval_seconds))
        });
        let mut crl = None;
        let mut crl_ok = true;
        if let Some(url) = cfg.crl_url.as_ref() {
            let source = CrlSource {
                store: Arc::new(
                    CrlStore::trusting(ca_bundle_pem).map_err(|e| format!("mtls crl: {e}"))?,
                ),
                url: url.clone(),
                period: interval(cfg.crl_refresh_interval_seconds),
                client: crl::fetch_client(fetch_roots),
                cache_path: cache_path.to_path_buf(),
            };
            source.load_cache();
            crl_ok = source.refresh().await;
            if !source.store.in_force() {
                error!(
                    url = %url,
                    "no CRL in force: fetch failed and no valid cached CRL; \
                     mTLS clients are refused until a CRL is applied"
                );
            }
            crl = Some(source);
        }
        Ok(Self {
            blocklist,
            crl,
            crl_ok,
        })
    }

    pub fn is_configured(&self) -> bool {
        self.blocklist.is_some() || self.crl.is_some()
    }

    pub fn attach(&self, mut validator: MtlsValidator) -> MtlsValidator {
        if let Some((list, _)) = &self.blocklist {
            validator = validator.with_blocklist(list.clone());
        }
        if let Some(source) = &self.crl {
            validator = validator.with_crl(source.store.clone());
        }
        validator
    }

    /// Refresh both sources until `shutdown` resolves.
    pub async fn run(mut self, shutdown: impl Future<Output = ()> + Send + 'static) {
        let mut blocklist_tick = ticker(self.blocklist.as_ref().map(|(_, d)| *d));
        let crl_sleep = tokio::time::sleep(self.crl_delay());
        tokio::pin!(shutdown, crl_sleep);
        loop {
            tokio::select! {
                _ = &mut shutdown => return,
                _ = blocklist_tick.tick(), if self.blocklist.is_some() => {
                    if let Some((list, _)) = &self.blocklist {
                        list.reload_if_changed();
                    }
                }
                _ = &mut crl_sleep, if self.crl.is_some() => {
                    if let Some(source) = &self.crl {
                        self.crl_ok = source.refresh().await;
                    }
                    crl_sleep.as_mut().reset(tokio::time::Instant::now() + self.crl_delay());
                }
            }
        }
    }

    fn crl_delay(&self) -> Duration {
        let period = self
            .crl
            .as_ref()
            .map_or(Duration::from_secs(3600), |c| c.period);
        if self.crl_ok {
            period
        } else {
            period.min(CRL_RETRY)
        }
    }
}

fn interval(seconds: u64) -> Duration {
    Duration::from_secs(seconds.max(1))
}

fn ticker(period: Option<Duration>) -> tokio::time::Interval {
    let period = period.unwrap_or(Duration::from_secs(3600));
    // The first tick would fire immediately; both sources were just
    // loaded, so start one period from now.
    let mut t = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
    t.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    t
}
