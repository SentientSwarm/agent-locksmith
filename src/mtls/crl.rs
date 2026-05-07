//! T6.3 — CRL fetcher and serial-set store.
//!
//! `CrlStore` is the in-memory snapshot the validator consults. It
//! holds:
//!  - The current set of revoked serials (lowercase hex).
//!  - The unix timestamp at which we last successfully refreshed.
//!  - A "fetch failures since last success" counter for metrics.
//!
//! The fetcher itself (`spawn_refresher`) runs as a background tokio
//! task. On refresh failure the prior snapshot stands — stale-but-up
//! beats fresh-and-down per Q-12. Callers observe staleness via
//! `age_secs()`; production deployments typically alert on
//! `age_secs() > 24 * crl_refresh_interval_seconds` or similar.

use arc_swap::ArcSwap;
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tracing::{info, warn};
use x509_parser::prelude::FromDer;

#[derive(Debug, Clone)]
pub struct CrlState {
    pub revoked_serials: HashSet<String>,
    pub last_success_unix_secs: i64,
}

#[derive(Debug)]
pub struct CrlStore {
    state: ArcSwap<CrlState>,
    failures: AtomicU64,
}

impl Default for CrlStore {
    fn default() -> Self {
        Self::new()
    }
}

impl CrlStore {
    pub fn new() -> Self {
        Self {
            state: ArcSwap::from_pointee(CrlState {
                revoked_serials: HashSet::new(),
                last_success_unix_secs: 0,
            }),
            failures: AtomicU64::new(0),
        }
    }

    pub fn contains(&self, serial_hex: &str) -> bool {
        self.state
            .load()
            .revoked_serials
            .contains(&serial_hex.to_ascii_lowercase())
    }

    pub fn snapshot(&self) -> Arc<CrlState> {
        self.state.load_full()
    }

    /// Seconds since the last successful refresh. `i64::MAX` if we
    /// have never succeeded. Drives the `mtls_crl_age_seconds` metric.
    pub fn age_secs(&self) -> i64 {
        let last = self.state.load().last_success_unix_secs;
        if last == 0 {
            return i64::MAX;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        now - last
    }

    /// Cumulative fetch failures since process start. Drives the
    /// `mtls_crl_refresh_failures_total` counter.
    pub fn refresh_failures_total(&self) -> u64 {
        self.failures.load(Ordering::Relaxed)
    }

    /// Apply a freshly-fetched PEM CRL. Replaces the snapshot
    /// atomically. Any parse error increments the failure counter and
    /// preserves the prior snapshot.
    pub fn apply_pem(&self, pem_bytes: &[u8]) -> Result<usize, CrlParseError> {
        let mut serials: HashSet<String> = HashSet::new();
        let mut crl_blocks_seen = 0;
        for block in pem::parse_many(pem_bytes).map_err(|e| CrlParseError::Pem(e.to_string()))? {
            if block.tag() != "X509 CRL" {
                continue;
            }
            crl_blocks_seen += 1;
            let (_, crl) =
                x509_parser::revocation_list::CertificateRevocationList::from_der(block.contents())
                    .map_err(|e| CrlParseError::Der(e.to_string()))?;
            for entry in crl.iter_revoked_certificates() {
                let serial = entry
                    .user_certificate
                    .to_bytes_be()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>();
                serials.insert(serial);
            }
        }
        if crl_blocks_seen == 0 {
            // No CRL blocks at all → treat as parse error so callers
            // know the snapshot was NOT replaced. Otherwise a garbage
            // PEM (or HTML error page from a misconfigured URL) would
            // silently empty out our revocation set.
            return Err(CrlParseError::Pem(
                "no `X509 CRL` PEM blocks in input".to_string(),
            ));
        }
        let len = serials.len();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        self.state.store(Arc::new(CrlState {
            revoked_serials: serials,
            last_success_unix_secs: now,
        }));
        info!(revoked_count = len, "CRL applied");
        Ok(len)
    }

    pub fn note_failure(&self) {
        self.failures.fetch_add(1, Ordering::Relaxed);
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CrlParseError {
    #[error("PEM parse: {0}")]
    Pem(String),
    #[error("DER parse: {0}")]
    Der(String),
}

/// Spawn a background refresher that fetches the CRL from `url` every
/// `interval`. Returns a JoinHandle the daemon can hold for clean
/// shutdown.
///
/// On every refresh:
///  - HTTP GET with a 10-second timeout (CRLs are typically small).
///  - On 2xx + parse-success: replace the snapshot.
///  - On any other outcome: log + bump failures counter; prior
///    snapshot stands.
pub async fn refresh_once(store: &CrlStore, url: &str) {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "CRL refresh: client build failed");
            store.note_failure();
            return;
        }
    };
    match client.get(url).send().await {
        Ok(resp) if resp.status().is_success() => match resp.bytes().await {
            Ok(body) => match store.apply_pem(&body) {
                Ok(_) => {}
                Err(e) => {
                    warn!(error = %e, "CRL refresh: parse failed; prior snapshot retained");
                    store.note_failure();
                }
            },
            Err(e) => {
                warn!(error = %e, "CRL refresh: read body failed");
                store.note_failure();
            }
        },
        Ok(resp) => {
            warn!(status = %resp.status(), "CRL refresh: non-success status");
            store.note_failure();
        }
        Err(e) => {
            warn!(error = %e, "CRL refresh: send failed");
            store.note_failure();
        }
    }
}
